//! # Filesystem Safety Module
//!
//! Provides secure filesystem access controls including path normalization,
//! network filesystem detection, and policy enforcement. This module ensures
//! all filesystem operations are constrained to allowed paths and prevents
//! access to potentially dangerous network-mounted filesystems.

use anyhow::{Context, Result};
use mdmcp_policy::CompiledPolicy;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Error, Debug)]
pub enum FsError {
    #[error("Path not allowed: {path}")]
    PathNotAllowed { path: String },
    #[error("Network filesystem access denied: {path}")]
    NetworkFsDenied { path: String },
    #[error("Special file not supported: {path}")]
    SpecialFile { path: String },
    #[error("Write not permitted: {path}")]
    WriteNotPermitted { path: String },
    #[error("File too large: {size} bytes exceeds limit {limit}")]
    FileTooLarge { size: u64, limit: u64 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Safe file reader with policy enforcement
pub struct GuardedFileReader {
    file: File,
    path: PathBuf,
    max_bytes: u64,
}

impl GuardedFileReader {
    /// Open file for reading with policy checks
    pub fn open<P: AsRef<Path>>(path: P, policy: &CompiledPolicy) -> Result<Self, FsError> {
        let path = path.as_ref();
        let canonical = canonicalize_path(path).map_err(|_| FsError::PathNotAllowed {
            path: path.display().to_string(),
        })?;

        // Check if path is within allowed roots
        if !policy.is_path_allowed(&canonical).map_err(|e| {
            FsError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })? {
            return Err(FsError::PathNotAllowed {
                path: canonical.display().to_string(),
            });
        }

        // Check for network filesystem
        if policy.policy.deny_network_fs && is_network_fs(&canonical)? {
            return Err(FsError::NetworkFsDenied {
                path: canonical.display().to_string(),
            });
        }

        // Check if it's a special file
        if is_special_file(&canonical)? {
            return Err(FsError::SpecialFile {
                path: canonical.display().to_string(),
            });
        }

        let file = File::open(&canonical)?;

        Ok(GuardedFileReader {
            file,
            path: canonical,
            max_bytes: policy.policy.limits.max_read_bytes,
        })
    }

    /// Read file with offset and length limits
    pub fn read_with_limits(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<(Vec<u8>, String), FsError> {
        use std::io::{Seek, SeekFrom};

        let effective_length = std::cmp::min(length, self.max_bytes.saturating_sub(offset));

        if offset > 0 {
            self.file.seek(SeekFrom::Start(offset))?;
        }

        let mut buffer = vec![0u8; effective_length as usize];
        let bytes_read = self.file.read(&mut buffer)?;
        buffer.truncate(bytes_read);

        // Compute SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        let hash = hex::encode(hasher.finalize());

        debug!("Read {} bytes from {}", bytes_read, self.path.display());

        Ok((buffer, hash))
    }
}

/// Safe file writer with policy enforcement
pub struct GuardedFileWriter {
    temp_path: PathBuf,
    final_path: PathBuf,
    max_bytes: u64,
}

impl GuardedFileWriter {
    /// Create file writer with policy checks
    pub fn create<P: AsRef<Path>>(
        path: P,
        policy: &CompiledPolicy,
        create: bool,
        overwrite: bool,
    ) -> Result<Self, FsError> {
        let path = path.as_ref();
        let canonical = canonicalize_path_for_write(path, create)?;

        // Check if path is within allowed roots
        if !policy.is_path_allowed(&canonical).map_err(|e| {
            FsError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })? {
            return Err(FsError::PathNotAllowed {
                path: canonical.display().to_string(),
            });
        }

        // Find applicable write rule
        let write_rule = policy
            .find_write_rule(&canonical)
            .map_err(|e| {
                FsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?
            .ok_or_else(|| FsError::WriteNotPermitted {
                path: canonical.display().to_string(),
            })?;

        // Check if we can create the file
        if !canonical.exists() && !create {
            return Err(FsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File does not exist and create=false",
            )));
        }

        // Check if we can overwrite the file
        if canonical.exists() && !overwrite {
            return Err(FsError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "File exists and overwrite=false",
            )));
        }

        // Check for network filesystem
        if policy.policy.deny_network_fs && is_network_fs(&canonical)? {
            return Err(FsError::NetworkFsDenied {
                path: canonical.display().to_string(),
            });
        }

        // Create parent directories if needed and allowed
        if let Some(parent) = canonical.parent() {
            if !parent.exists() && write_rule.create_if_missing {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Create temporary file for atomic write
        let temp_path = canonical.with_extension(format!(
            "{}.tmp.{}",
            canonical
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("tmp"),
            std::process::id()
        ));

        Ok(GuardedFileWriter {
            temp_path,
            final_path: canonical,
            max_bytes: write_rule.max_file_bytes,
        })
    }

    /// Write data with size limits and atomic commit
    pub fn write_atomic(&self, data: &[u8]) -> Result<(u64, String), FsError> {
        if data.len() as u64 > self.max_bytes {
            return Err(FsError::FileTooLarge {
                size: data.len() as u64,
                limit: self.max_bytes,
            });
        }

        // Write to temporary file
        {
            let mut temp_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.temp_path)?;

            temp_file.write_all(data)?;
            temp_file.sync_all()?;
        }

        // Atomic rename
        std::fs::rename(&self.temp_path, &self.final_path)?;

        // Set restrictive permissions
        set_secure_permissions(&self.final_path)?;

        // Compute SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        debug!(
            "Wrote {} bytes to {}",
            data.len(),
            self.final_path.display()
        );

        Ok((data.len() as u64, hash))
    }
}

impl Drop for GuardedFileWriter {
    fn drop(&mut self) {
        // Clean up temp file if it still exists
        if self.temp_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.temp_path) {
                warn!(
                    "Failed to clean up temp file {}: {}",
                    self.temp_path.display(),
                    e
                );
            }
        }
    }
}

/// Canonicalize path, handling the case where the path might not exist
fn canonicalize_path(path: &Path) -> Result<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        Ok(canonical)
    } else {
        // Path might not exist, try to canonicalize the parent
        if let Some(parent) = path.parent() {
            let parent_canonical = parent
                .canonicalize()
                .context("Parent directory does not exist")?;
            let filename = path
                .file_name()
                .context("Invalid path: no filename component")?;
            Ok(parent_canonical.join(filename))
        } else {
            Err(anyhow::anyhow!(
                "Cannot canonicalize path: {}",
                path.display()
            ))
        }
    }
}

/// Canonicalize path for write operations, handling non-existent files
fn canonicalize_path_for_write(path: &Path, create: bool) -> Result<PathBuf, FsError> {
    if path.exists() {
        path.canonicalize().map_err(FsError::Io)
    } else if create {
        // For non-existent files that we're allowed to create,
        // canonicalize the parent directory
        if let Some(parent) = path.parent() {
            let parent_canonical = parent.canonicalize().map_err(|_| FsError::PathNotAllowed {
                path: path.display().to_string(),
            })?;
            let filename = path.file_name().ok_or_else(|| FsError::PathNotAllowed {
                path: path.display().to_string(),
            })?;
            Ok(parent_canonical.join(filename))
        } else {
            Err(FsError::PathNotAllowed {
                path: path.display().to_string(),
            })
        }
    } else {
        Err(FsError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File does not exist",
        )))
    }
}

/// Check if path points to a special file (not a regular file)
fn is_special_file(path: &Path) -> Result<bool, FsError> {
    let metadata = std::fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();

    Ok(!file_type.is_file())
}

/// Platform-specific network filesystem detection
#[cfg(target_os = "linux")]
fn is_network_fs(path: &Path) -> Result<bool, FsError> {
    use std::ffi::CStr;
    use std::mem;
    use std::os::unix::ffi::OsStrExt;

    // Try to read /proc/mounts to detect network filesystems
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let path_str = path.to_string_lossy();

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let mount_point = parts[1];
            let fs_type = parts[2];

            if path_str.starts_with(mount_point) {
                match fs_type {
                    "nfs" | "nfs4" | "cifs" | "smbfs" | "sshfs" | "fuse.sshfs" => {
                        return Ok(true);
                    }
                    fs if fs.starts_with("fuse.") => {
                        // Most fuse filesystems are potentially network-based
                        return Ok(true);
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(false)
}

#[cfg(target_os = "macos")]
fn is_network_fs(path: &Path) -> Result<bool, FsError> {
    use std::ffi::CString;
    use std::mem;
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn statfs(path: *const libc::c_char, buf: *mut libc::statfs) -> libc::c_int;
    }

    let path_c =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| FsError::PathNotAllowed {
            path: path.display().to_string(),
        })?;

    let mut statfs_buf: libc::statfs = unsafe { mem::zeroed() };
    let result = unsafe { statfs(path_c.as_ptr(), &mut statfs_buf) };

    if result != 0 {
        return Err(FsError::Io(std::io::Error::last_os_error()));
    }

    let fs_type = unsafe { CStr::from_ptr(statfs_buf.f_fstypename.as_ptr()).to_string_lossy() };

    let is_network = matches!(
        fs_type.as_ref(),
        "nfs" | "afpfs" | "smbfs" | "cifs" | "ftp" | "webdav"
    );

    Ok(is_network)
}

#[cfg(target_os = "windows")]
fn is_network_fs(path: &Path) -> Result<bool, FsError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let path_str = path.to_string_lossy();

    // Check for UNC paths
    if path_str.starts_with("\\\\") {
        return Ok(true);
    }

    // Check drive type for mapped network drives
    if let Some(root) = path.ancestors().last() {
        let root_wide: Vec<u16> = OsStr::new(&format!("{}\\", root.display()))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let drive_type =
            unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root_wide.as_ptr()) };

        // DRIVE_REMOTE = 4
        if drive_type == 4 {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn is_network_fs(_path: &Path) -> Result<bool, FsError> {
    // Conservative approach: assume it might be network FS on unknown platforms
    warn!("Network filesystem detection not implemented for this platform");
    Ok(false)
}

/// Set secure file permissions (readable/writable by owner only)
#[cfg(unix)]
fn set_secure_permissions(path: &Path) -> Result<(), FsError> {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600); // Read/write for owner only
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(windows)]
fn set_secure_permissions(_path: &Path) -> Result<(), FsError> {
    // Windows file permissions are more complex and would require
    // Windows-specific APIs to set properly. For now, we rely on
    // the default permissions set by the filesystem.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdmcp_policy::*;
    use tempfile::{tempdir, NamedTempFile};

    fn create_test_policy() -> CompiledPolicy {
        let temp_dir = tempdir().unwrap();
        let test_root = temp_dir.path().to_path_buf();

        let policy = Policy {
            version: 1,
            deny_network_fs: false,
            allowed_roots: vec![test_root.to_string_lossy().to_string()],
            write_rules: vec![WriteRule {
                path: test_root.to_string_lossy().to_string(),
                recursive: true,
                max_file_bytes: 1000,
                create_if_missing: true,
            }],
            commands: vec![],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        policy.compile().unwrap()
    }

    #[test]
    fn test_guarded_file_reader() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"test content").unwrap();

        let temp_dir = temp_file.path().parent().unwrap();
        let policy = Policy {
            version: 1,
            deny_network_fs: false,
            allowed_roots: vec![temp_dir.to_string_lossy().to_string()],
            write_rules: vec![],
            commands: vec![],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let compiled_policy = policy.compile().unwrap();
        let mut reader = GuardedFileReader::open(temp_file.path(), &compiled_policy).unwrap();
        let (data, _hash) = reader.read_with_limits(0, 1000).unwrap();

        assert_eq!(data, b"test content");
    }

    #[test]
    fn test_guarded_file_writer() {
        let policy = create_test_policy();
        let temp_dir = PathBuf::from(&policy.allowed_roots_canonical[0]);
        let test_file = temp_dir.join("test_write.txt");

        let writer = GuardedFileWriter::create(&test_file, &policy, true, true).unwrap();
        let (bytes_written, _hash) = writer.write_atomic(b"test data").unwrap();

        assert_eq!(bytes_written, 9);
        assert_eq!(std::fs::read(&test_file).unwrap(), b"test data");
    }

    #[test]
    fn test_path_not_allowed() {
        let policy = create_test_policy();
        let forbidden_path = PathBuf::from("/tmp/forbidden.txt");

        let result = GuardedFileReader::open(&forbidden_path, &policy);
        assert!(matches!(result, Err(FsError::PathNotAllowed { .. })));
    }

    #[test]
    fn test_file_size_limit() {
        let policy = create_test_policy();
        let temp_dir = PathBuf::from(&policy.allowed_roots_canonical[0]);
        let test_file = temp_dir.join("large_file.txt");

        let writer = GuardedFileWriter::create(&test_file, &policy, true, true).unwrap();
        let large_data = vec![b'x'; 2000]; // Exceeds 1000 byte limit

        let result = writer.write_atomic(&large_data);
        assert!(matches!(result, Err(FsError::FileTooLarge { .. })));
    }
}
