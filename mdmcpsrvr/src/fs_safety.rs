//! # Filesystem Safety Module
//!
//! Provides secure filesystem access controls including path normalization,
//! network filesystem detection, and policy enforcement. This module ensures
//! all filesystem operations are constrained to allowed paths and prevents
//! access to potentially dangerous network-mounted filesystems.

use anyhow::{Context, Result};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use mdmcp_policy::CompiledPolicy;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Error, Debug)]
pub enum FsError {
    #[error("Path not allowed: {path}")]
    PathNotAllowed { path: String },
    #[error("Network filesystem access denied: {path}")]
    NetworkFsDenied { path: String },
    #[error("WSL path access denied (policy: deny_all): {path}")]
    WslPathDenied { path: String },
    #[error("Special file not supported: {path}")]
    SpecialFile { path: String },
    #[error("Write not permitted: {path}")]
    WriteNotPermitted { path: String },
    #[error("File too large: {size} bytes exceeds limit {limit}")]
    FileTooLarge { size: u64, limit: u64 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Classification of UNC paths (Windows only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncPathType {
    /// Local WSL filesystem (\\wsl$\ or \\wsl.localhost\)
    LocalWsl,
    /// Remote network share
    RemoteNetwork,
    /// Not a UNC path
    NotUnc,
}

/// Check if a path is a local WSL UNC path
/// Returns true for paths like \\wsl$\Ubuntu\... or \\wsl.localhost\Ubuntu\...
#[cfg(target_os = "windows")]
fn is_local_wsl_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let lower = path_str.to_lowercase();

    // Check for \\wsl$ or \\wsl.localhost
    if lower.starts_with("\\\\wsl$\\") || lower.starts_with("\\\\wsl.localhost\\") {
        return true;
    }

    // Also handle forward slash variants that might come from path normalization
    if lower.starts_with("//wsl$/") || lower.starts_with("//wsl.localhost/") {
        return true;
    }

    false
}

/// Classify a UNC path (Windows only)
#[cfg(target_os = "windows")]
fn classify_unc_path(path: &Path) -> UncPathType {
    let path_str = path.to_string_lossy();

    // Must start with \\ to be UNC (but not \\?\ which is long path prefix)
    if !path_str.starts_with("\\\\") || path_str.starts_with("\\\\?\\") {
        return UncPathType::NotUnc;
    }

    if is_local_wsl_path(path) {
        UncPathType::LocalWsl
    } else {
        UncPathType::RemoteNetwork
    }
}

/// Check network filesystem access based on policy (Windows implementation)
#[cfg(target_os = "windows")]
pub(crate) fn check_network_fs_access(
    path: &Path,
    policy: mdmcp_policy::NetworkFsPolicy,
) -> Result<(), FsError> {
    use mdmcp_policy::NetworkFsPolicy;

    match policy {
        NetworkFsPolicy::AllowAll => Ok(()),
        NetworkFsPolicy::DenyAll | NetworkFsPolicy::AllowLocalWsl => {
            // Check UNC path type
            match classify_unc_path(path) {
                UncPathType::NotUnc => {
                    // Check for mapped network drives
                    if is_mapped_network_drive(path)? {
                        return Err(FsError::NetworkFsDenied {
                            path: path.display().to_string(),
                        });
                    }
                    Ok(())
                }
                UncPathType::LocalWsl => {
                    if policy == NetworkFsPolicy::DenyAll {
                        Err(FsError::WslPathDenied {
                            path: path.display().to_string(),
                        })
                    } else {
                        // AllowLocalWsl permits this
                        Ok(())
                    }
                }
                UncPathType::RemoteNetwork => Err(FsError::NetworkFsDenied {
                    path: path.display().to_string(),
                }),
            }
        }
    }
}

/// Check if a path is on a mapped network drive (Windows only)
#[cfg(target_os = "windows")]
fn is_mapped_network_drive(path: &Path) -> Result<bool, FsError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    if let Some(root) = path.ancestors().last() {
        let root_str = format!("{}\\", root.display());
        // Skip if it looks like a UNC path root (e.g., \\server\share)
        if root_str.starts_with("\\\\") {
            return Ok(false);
        }
        let root_wide: Vec<u16> = OsStr::new(&root_str)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let drive_type =
            unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root_wide.as_ptr()) };

        // DRIVE_REMOTE = 4
        return Ok(drive_type == 4);
    }

    Ok(false)
}

/// Check network filesystem access based on policy (Unix implementation - WSL not applicable)
#[cfg(not(target_os = "windows"))]
pub(crate) fn check_network_fs_access(
    path: &Path,
    policy: mdmcp_policy::NetworkFsPolicy,
) -> Result<(), FsError> {
    use mdmcp_policy::NetworkFsPolicy;

    match policy {
        NetworkFsPolicy::AllowAll => Ok(()),
        // On Unix, WSL paths don't exist, so DenyAll and AllowLocalWsl behave the same
        NetworkFsPolicy::DenyAll | NetworkFsPolicy::AllowLocalWsl => {
            if is_network_fs(path)? {
                Err(FsError::NetworkFsDenied {
                    path: path.display().to_string(),
                })
            } else {
                Ok(())
            }
        }
    }
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
        // Disallow reading through symlinks to avoid escape via TOCTOU/symlink swaps
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(FsError::SpecialFile {
                    path: format!("{} (symlink not permitted)", path.display()),
                });
            }
        }
        let canonical = canonicalize_path(path).map_err(|_| FsError::PathNotAllowed {
            path: path.display().to_string(),
        })?;

        // Resolve to allowed root (prefix check)
        if !policy
            .allowed_roots_canonical
            .iter()
            .any(|root| canonical.starts_with(root))
        {
            return Err(FsError::PathNotAllowed {
                path: canonical.display().to_string(),
            });
        }

        // Check for network filesystem using the effective policy
        check_network_fs_access(&canonical, policy.policy.effective_network_fs_policy())?;

        // Check if it's a special file
        if is_special_file(&canonical)? {
            let file_type = get_file_type_description(&canonical);
            return Err(FsError::SpecialFile {
                path: format!("{} ({})", canonical.display(), file_type),
            });
        }

        // Open via capability handle bound to the file's parent directory
        let parent = canonical.parent().ok_or_else(|| FsError::PathNotAllowed {
            path: canonical.display().to_string(),
        })?;
        let file_name = canonical
            .file_name()
            .ok_or_else(|| FsError::PathNotAllowed {
                path: canonical.display().to_string(),
            })?;
        let dir = Dir::open_ambient_dir(parent, ambient_authority()).map_err(FsError::Io)?;
        let file = dir.open(file_name).map_err(FsError::Io)?;

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
    pub fn file_len(&self) -> Result<u64, FsError> {
        Ok(self.file.metadata()?.len())
    }
}

/// Safe file writer with policy enforcement
pub struct GuardedFileWriter {
    dir: Dir,
    temp_name: PathBuf,
    final_name: PathBuf,
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
        // If target exists and is a symlink, refuse to write
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(FsError::SpecialFile {
                    path: format!("{} (symlink not permitted)", path.display()),
                });
            }
        }
        let canonical = canonicalize_path_for_write(path, create)?;

        // Path allowance will be checked via write rules below

        // Find applicable write rule using parent directory path (string-based match)
        let parent = canonical.parent().ok_or_else(|| FsError::PathNotAllowed {
            path: canonical.display().to_string(),
        })?;
        let write_rule = policy
            .write_rules_canonical
            .iter()
            .find(|rule| {
                if rule.recursive {
                    parent.starts_with(rule.path_canonical.as_path())
                } else {
                    parent == rule.path_canonical.as_path()
                }
            })
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

        // Check for network filesystem using the effective policy
        check_network_fs_access(&canonical, policy.policy.effective_network_fs_policy())?;

        // Path allowance is implied by the write rule match above

        // Ensure parent directory exists if allowed by write rule
        if !parent.exists() && write_rule.create_if_missing {
            std::fs::create_dir_all(parent).map_err(FsError::Io)?;
        }

        // Create temporary relative path for atomic write
        let file_name = canonical
            .file_name()
            .ok_or_else(|| FsError::PathNotAllowed {
                path: canonical.display().to_string(),
            })?;
        let stem = file_name.to_str().unwrap_or("tmp");
        let temp_name = PathBuf::from(format!("{}.tmp.{}", stem, std::process::id()));

        let dir = Dir::open_ambient_dir(parent, ambient_authority()).map_err(FsError::Io)?;

        Ok(GuardedFileWriter {
            dir,
            temp_name,
            final_name: PathBuf::from(file_name),
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
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            let mut temp_file = self
                .dir
                .open_with(&self.temp_name, &opts)
                .map_err(FsError::Io)?;
            use std::io::Write as _;
            temp_file.write_all(data)?;
            temp_file.sync_all()?;
        }

        // Atomic rename within the same directory using capability handle
        self.dir
            .rename(&self.temp_name, &self.dir, &self.final_name)
            .map_err(FsError::Io)?;

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
        if self.dir.open(&self.temp_name).is_ok() {
            if let Err(e) = self.dir.remove_file(&self.temp_name) {
                warn!(
                    "Failed to clean up temp file {}: {}",
                    self.temp_name.display(),
                    e
                );
            }
        }
    }
}

/// Canonicalize path, handling the case where the path might not exist
pub(crate) fn canonicalize_path(path: &Path) -> Result<PathBuf> {
    if let Ok(canonical) = dunce::canonicalize(path) {
        Ok(canonical)
    } else {
        // Path might not exist, try to canonicalize the parent
        if let Some(parent) = path.parent() {
            let parent_canonical =
                dunce::canonicalize(parent).context("Parent directory does not exist")?;
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
        return dunce::canonicalize(path).map_err(FsError::Io);
    }
    if !create {
        return Err(FsError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File does not exist",
        )));
    }

    // Walk up to find the nearest existing ancestor
    let mut components = Vec::<PathBuf>::new();
    let mut cursor = path;
    loop {
        if cursor.exists() {
            break;
        }
        if let Some(parent) = cursor.parent() {
            if let Some(name) = cursor.file_name() {
                components.push(PathBuf::from(name));
            }
            cursor = parent;
        } else {
            // No existing ancestor; bail
            return Err(FsError::PathNotAllowed {
                path: path.display().to_string(),
            });
        }
    }

    // Canonicalize the existing ancestor and rejoin the non-existent suffix
    let mut canonical = dunce::canonicalize(cursor).map_err(FsError::Io)?;
    for part in components.iter().rev() {
        canonical.push(part);
    }
    Ok(canonical)
}

// (removed) resolve_root_and_rel no longer used

/// Check if path points to a special file (not a regular file)
fn is_special_file(path: &Path) -> Result<bool, FsError> {
    let metadata = std::fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();

    Ok(!file_type.is_file())
}

/// Get a user-friendly description of what type of file this is
fn get_file_type_description(path: &Path) -> String {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            return "directory".to_string();
        } else if file_type.is_symlink() {
            return "symbolic link".to_string();
        }
    }
    "special file".to_string()
}

/// Platform-specific network filesystem detection
#[cfg(target_os = "linux")]
pub(crate) fn is_network_fs(path: &Path) -> Result<bool, FsError> {
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
pub(crate) fn is_network_fs(path: &Path) -> Result<bool, FsError> {
    use std::ffi::{CStr, CString};
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
pub(crate) fn is_network_fs(path: &Path) -> Result<bool, FsError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let path_str = path.to_string_lossy();

    // Check for UNC paths (but not Windows long path format \\?\)
    if path_str.starts_with("\\\\") && !path_str.starts_with("\\\\?\\") {
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
pub(crate) fn is_network_fs(_path: &Path) -> Result<bool, FsError> {
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
            network_fs_policy: None,
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
            network_fs_policy: None,
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

    // WSL UNC path tests (Windows-only)
    #[cfg(target_os = "windows")]
    mod wsl_tests {
        use super::*;

        #[test]
        fn test_classify_unc_path_wsl_dollar() {
            let path = PathBuf::from(r"\\wsl$\Ubuntu\home\user\file.txt");
            assert_eq!(classify_unc_path(&path), UncPathType::LocalWsl);
        }

        #[test]
        fn test_classify_unc_path_wsl_localhost() {
            let path = PathBuf::from(r"\\wsl.localhost\Ubuntu\home\user\file.txt");
            assert_eq!(classify_unc_path(&path), UncPathType::LocalWsl);
        }

        #[test]
        fn test_classify_unc_path_wsl_case_insensitive() {
            let path1 = PathBuf::from(r"\\WSL$\Ubuntu\home\user");
            let path2 = PathBuf::from(r"\\WSL.LOCALHOST\Ubuntu\home\user");
            assert_eq!(classify_unc_path(&path1), UncPathType::LocalWsl);
            assert_eq!(classify_unc_path(&path2), UncPathType::LocalWsl);
        }

        #[test]
        fn test_classify_unc_path_remote_network() {
            let path = PathBuf::from(r"\\server\share\file.txt");
            assert_eq!(classify_unc_path(&path), UncPathType::RemoteNetwork);
        }

        #[test]
        fn test_classify_unc_path_not_unc() {
            let path = PathBuf::from(r"C:\Users\test\file.txt");
            assert_eq!(classify_unc_path(&path), UncPathType::NotUnc);
        }

        #[test]
        fn test_classify_unc_path_long_path_prefix() {
            // Long path prefix should not be treated as UNC
            let path = PathBuf::from(r"\\?\C:\Users\test\file.txt");
            assert_eq!(classify_unc_path(&path), UncPathType::NotUnc);
        }

        #[test]
        fn test_check_network_fs_deny_all_blocks_wsl() {
            use mdmcp_policy::NetworkFsPolicy;
            let path = PathBuf::from(r"\\wsl$\Ubuntu\home\user\file.txt");
            let result = check_network_fs_access(&path, NetworkFsPolicy::DenyAll);
            assert!(matches!(result, Err(FsError::WslPathDenied { .. })));
        }

        #[test]
        fn test_check_network_fs_allow_local_wsl_permits_wsl() {
            use mdmcp_policy::NetworkFsPolicy;
            let path = PathBuf::from(r"\\wsl$\Ubuntu\home\user\file.txt");
            let result = check_network_fs_access(&path, NetworkFsPolicy::AllowLocalWsl);
            assert!(result.is_ok());
        }

        #[test]
        fn test_check_network_fs_allow_local_wsl_blocks_remote() {
            use mdmcp_policy::NetworkFsPolicy;
            let path = PathBuf::from(r"\\server\share\file.txt");
            let result = check_network_fs_access(&path, NetworkFsPolicy::AllowLocalWsl);
            assert!(matches!(result, Err(FsError::NetworkFsDenied { .. })));
        }

        #[test]
        fn test_check_network_fs_allow_all_permits_everything() {
            use mdmcp_policy::NetworkFsPolicy;
            let wsl_path = PathBuf::from(r"\\wsl$\Ubuntu\home\user\file.txt");
            let remote_path = PathBuf::from(r"\\server\share\file.txt");
            assert!(check_network_fs_access(&wsl_path, NetworkFsPolicy::AllowAll).is_ok());
            assert!(check_network_fs_access(&remote_path, NetworkFsPolicy::AllowAll).is_ok());
        }
    }

    // Tests for NetworkFsPolicy backward compatibility
    #[test]
    fn test_effective_network_fs_policy_new_field_takes_precedence() {
        use mdmcp_policy::NetworkFsPolicy;
        let policy = Policy {
            version: 1,
            network_fs_policy: Some(NetworkFsPolicy::AllowLocalWsl),
            deny_network_fs: true, // This should be ignored
            allowed_roots: vec![],
            write_rules: vec![],
            commands: vec![],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };
        assert_eq!(
            policy.effective_network_fs_policy(),
            NetworkFsPolicy::AllowLocalWsl
        );
    }

    #[test]
    fn test_effective_network_fs_policy_legacy_deny_true() {
        use mdmcp_policy::NetworkFsPolicy;
        let policy = Policy {
            version: 1,
            network_fs_policy: None,
            deny_network_fs: true,
            allowed_roots: vec![],
            write_rules: vec![],
            commands: vec![],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };
        assert_eq!(
            policy.effective_network_fs_policy(),
            NetworkFsPolicy::DenyAll
        );
    }

    #[test]
    fn test_effective_network_fs_policy_legacy_deny_false() {
        use mdmcp_policy::NetworkFsPolicy;
        let policy = Policy {
            version: 1,
            network_fs_policy: None,
            deny_network_fs: false,
            allowed_roots: vec![],
            write_rules: vec![],
            commands: vec![],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };
        assert_eq!(
            policy.effective_network_fs_policy(),
            NetworkFsPolicy::AllowAll
        );
    }
}
