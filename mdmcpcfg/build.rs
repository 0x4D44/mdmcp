fn main() {
    // Embed Windows version resource + icon (no-op on non-Windows)
    #[cfg(windows)]
    {
        embed_windows_resources(
            "MDMCP Config CLI (install, update, policy)",
            "mdmcpcfg",
            "mdmcpcfg.exe",
        );
    }
}

#[cfg(windows)]
fn embed_windows_resources(desc: &str, internal: &str, original: &str) {
    let mut res = winres::WindowsResource::new();
    // Versions
    let ver = env!("CARGO_PKG_VERSION");
    res.set("FileVersion", ver);
    res.set("ProductVersion", ver);
    // Strings
    res.set("ProductName", "MDMCP");
    res.set("FileDescription", desc);
    res.set("CompanyName", "Martin Davidson");
    res.set("OriginalFilename", original);
    res.set("InternalName", internal);
    res.set("Comments", "https://github.com/0x4D44/mdmcp");
    res.set("LegalCopyright", "(C) Martin Davidson 2025");

    // Icon if present
    let icon_path = std::path::Path::new("res").join("mdmcpcfg.ico");
    if icon_path.exists() {
        if let Some(p) = icon_path.to_str() {
            res.set_icon(p);
        }
    }

    // Ignore errors to avoid breaking non-Windows environments unexpectedly
    let _ = res.compile();
}
