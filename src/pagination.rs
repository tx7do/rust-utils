//! 分页偏移量计算(移植自 go-utils/pagination)。

/// 默认页码。
pub const DEFAULT_PAGE: i32 = 1;
/// 默认每页行数。
pub const DEFAULT_PAGE_SIZE: i32 = 10;

/// 计算数据库查询偏移量(offset)。
///
/// ```
/// use rust_utils::pagination;
/// assert_eq!(pagination::get_page_offset(1, 10), 0);
/// assert_eq!(pagination::get_page_offset(3, 10), 20);
/// ```
pub fn get_page_offset(page_num: i32, page_size: i32) -> i64 {
    (page_num as i64 - 1) * page_size as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_page_offset() {
        assert_eq!(get_page_offset(1, 10), 0);
        assert_eq!(get_page_offset(2, 10), 10);
        assert_eq!(get_page_offset(3, 10), 20);
        assert_eq!(get_page_offset(0, 10), -10);
    }
}
