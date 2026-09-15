//! 文件系统与路径辅助。
//!
//! glob 模式匹配([`match_path`])位于 `glob` feature 下。

use std::io;
use std::path::{Path, PathBuf};

/// 获取当前工作目录(失败时 panic)。
pub fn working_dir() -> PathBuf {
    std::env::current_dir().expect("get working dir failed")
}

/// 获取可执行程序所在目录(失败时 panic)。
pub fn exe_path() -> PathBuf {
    let exe = std::env::current_exe().expect("get exe path failed");
    exe.parent().map(Path::to_path_buf).unwrap_or(exe)
}

/// 递归列出 `root` 下的所有文件路径;失败时返回空。
pub fn file_list(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_files(root, &mut out);
    out
}

fn walk_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// 列出 `root` 下的子文件夹名(一层,不递归)。
pub fn folder_name_list(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

/// 把路径中的 `~` 展开为当前用户主目录。
///
/// ```
/// use rust_utils::fsutil::expand_user;
///
/// assert_eq!(expand_user("/abs/path"), "/abs/path");
/// let expanded = expand_user("~/data");
/// assert!(!expanded.starts_with('~'));
/// ```
pub fn expand_user(path: &str) -> String {
    if path == "~" || path.starts_with("~/") || (cfg!(windows) && path.starts_with("~\\")) {
        if let Some(home) = home_dir() {
            return path.replacen('~', &home, 1);
        }
    }
    path.to_string()
}

fn home_dir() -> Option<String> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok()
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").ok()
    }
}

/// 路径是否存在(跟随符号链接)。
pub fn exists(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

/// 路径是否存在且为符号链接。
pub fn link_exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// 路径是否存在且为普通文件。
pub fn file_exists(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// 路径是否存在且为目录。
pub fn dir_exists(path: &Path) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

/// [`exists`] 的别名。
pub fn path_exist(path: &Path) -> bool {
    exists(path)
}

/// 是否为非空的普通文件。
pub fn is_nonempty_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false)
}

/// 是否为内容非空的目录。
pub fn is_nonempty_dir(path: &Path) -> bool {
    std::fs::read_dir(path)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
}

/// 是否为非空且对当前用户可执行的文件(仅类 Unix 平台检查执行位)。
pub fn is_nonempty_executable_file(path: &Path) -> bool {
    if !is_nonempty_file(path) {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// 读取文件;失败返回 `None`。
pub fn read_file(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// 文件是否可读(实际打开测试)。
pub fn is_readable(path: &Path) -> bool {
    std::fs::File::open(path).is_ok()
}

/// 文件是否可写(实际打开测试)。
pub fn is_writable(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_ok()
}

/// 文件是否可追加(实际打开测试)。
pub fn is_appendable(path: &Path) -> bool {
    std::fs::OpenOptions::new().append(true).open(path).is_ok()
}

/// glob 模式匹配路径(基于 `glob` crate 的模式语法,支持 `*`、`**`、`?` 等)。
#[cfg(feature = "glob")]
pub fn match_path(pattern: &str, path: &str) -> bool {
    match glob::Pattern::new(pattern) {
        Ok(p) => p.matches(path),
        Err(_) => false,
    }
}

/// 把相对路径转为绝对路径(基于当前工作目录)。
pub fn abs_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(working_dir().join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_exists_family() {
        let dir = std::env::temp_dir().join(format!("rust-utils-test-{}", std::process::id()));
        let file = dir.join("a.txt");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"hello").unwrap();

        assert!(exists(&dir));
        assert!(dir_exists(&dir));
        assert!(path_exist(&dir));
        assert!(file_exists(&file));
        assert!(is_nonempty_file(&file));
        assert!(is_nonempty_dir(&dir));
        assert!(is_readable(&file));
        assert!(is_writable(&file));
        assert!(is_appendable(&file));

        let missing = dir.join("nope");
        assert!(!exists(&missing));
        assert!(!file_exists(&missing));
        assert!(!dir_exists(&missing));
        assert!(!is_nonempty_file(&missing));

        assert_eq!(read_file(&file).as_deref(), Some(&b"hello"[..]));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_expand_user() {
        assert_eq!(expand_user("/abs/path"), "/abs/path");
        assert_eq!(expand_user(""), "");
        let expanded = expand_user("~/data");
        assert!(!expanded.starts_with('~'));
    }

    #[test]
    fn test_lists_and_paths() {
        let dir = std::env::temp_dir().join(format!("rust-utils-list-{}", std::process::id()));
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(dir.join("x.txt"), b"1").unwrap();
        fs::write(sub.join("y.txt"), b"2").unwrap();

        let files = file_list(&dir);
        assert_eq!(files.len(), 2);

        let folders = folder_name_list(&dir);
        assert_eq!(folders, vec!["sub"]);

        assert!(abs_path(Path::new("rel.txt")).is_ok());
        assert!(file_list(&dir).iter().all(|p| p.is_absolute()));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_link_exists() {
        let dir = std::env::temp_dir().join(format!("rust-utils-link-{}", std::process::id()));
        let file = dir.join("target.txt");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"x").unwrap();
        let link = dir.join("alias.txt");

        // Windows 上创建符号链接需要开发者模式/管理员权限,失败则跳过
        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(&file, &link).is_ok();
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_file(&file, &link).is_ok();

        if created {
            assert!(link_exists(&link));
            // file_exists 跟随符号链接
            assert!(file_exists(&link));
            assert!(file_exists(&file));
            std::fs::remove_file(&link).unwrap();
        }
        assert!(!link_exists(&file));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_is_nonempty_executable_file() {
        let dir = std::env::temp_dir().join(format!("rust-utils-exe-{}", std::process::id()));
        let file = dir.join("tool.bin");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            &file,
            b"#!/bin/sh
",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // 无执行位 → false
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(!is_nonempty_executable_file(&file));
            // 有执行位 → true
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(is_nonempty_executable_file(&file));
        }
        #[cfg(not(unix))]
        {
            // Windows 无执行位概念,非空普通文件即可
            assert!(is_nonempty_executable_file(&file));
        }

        // 空文件永远不算
        let empty = dir.join("empty.bin");
        fs::write(&empty, b"").unwrap();
        assert!(!is_nonempty_executable_file(&empty));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "glob")]
    #[test]
    fn test_match_path() {
        assert!(match_path("*.txt", "main.txt"));
        assert!(!match_path("*.txt", "main.rs"));
        assert!(match_path("src/**/*.rs", "src/a/b.rs"));
    }
}
