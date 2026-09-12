//! 数值与统计辅助,含手写实现的正态分布(移植自 go-utils/math)。
//!
//! 求和用 `iter().sum()`,符号函数见 [`sign`]。

/// 符号函数(sgn):负数返回 -1,正数返回 +1,零返回 0。
pub fn sign<T: Signed>(x: T) -> T {
    x.sign()
}

/// 可取符号的数值类型抽象,覆盖 Go 版 `Sign` 支持的全部类型。
pub trait Signed: Copy {
    fn sign(self) -> Self;
}

macro_rules! impl_signed_int {
    ($($t:ty),*) => {$(
        impl Signed for $t {
            fn sign(self) -> Self {
                if self < 0 { -1 } else if self > 0 { 1 } else { 0 }
            }
        }
    )*};
}
impl_signed_int!(i8, i16, i32, i64, i128, isize);

macro_rules! impl_signed_float {
    ($($t:ty),*) => {$(
        impl Signed for $t {
            fn sign(self) -> Self {
                if self < 0.0 { -1.0 } else if self > 0.0 { 1.0 } else { 0.0 }
            }
        }
    )*};
}
impl_signed_float!(f32, f64);

/// 计算平均值;空切片返回 NaN。
pub fn mean(nums: &[f64]) -> f64 {
    let sum: f64 = nums.iter().sum();
    sum / nums.len() as f64
}

/// 用给定的平均值计算方差(总体方差,除以 N)。
pub fn variance(mean: f64, nums: &[f64]) -> f64 {
    let acc: f64 = nums.iter().map(|x| (x - mean).powi(2)).sum();
    acc / nums.len() as f64
}

/// 计算标准差。
pub fn standard_deviation(nums: &[f64]) -> f64 {
    variance(mean(nums), nums).sqrt()
}

/// 补余误差函数,取自 Numerical Recipes in C 2e p221。
pub fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + z / 2.0);
    let r = t
        * (-z * z - 1.26551223
            + t * (1.00002368
                + t * (0.37409196
                    + t * (0.09678418
                        + t * (-0.18628806
                            + t * (0.27886807
                                + t * (-1.13520398
                                    + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))))
            .exp();
    if x >= 0.0 {
        r
    } else {
        2.0 - r
    }
}

/// 逆补余误差函数,取自 Numerical Recipes 3e p265。
/// 其中的常量为该算法的固定拟合系数,不可替换为精确数学常量。
#[allow(clippy::approx_constant)]
pub fn ierfc(x: f64) -> f64 {
    if x >= 2.0 {
        return -100.0;
    }
    if x <= 0.0 {
        return 100.0;
    }
    let xx = if x < 1.0 { x } else { 2.0 - x };
    let t = (-2.0 * (xx / 2.0).ln()).sqrt();
    let mut r = -0.70711 * ((2.30753 + t * 0.27061) / (1.0 + t * (0.99229 + t * 0.04481)) - t);
    for _ in 0..2 {
        let e = erfc(r) - xx;
        r += e / (1.128_379_167_095_512_6 * (-(r * r)).exp() - r * e);
    }
    if x < 1.0 {
        r
    } else {
        -r
    }
}

/// 正态分布(N(μ, σ²)),支持密度/分布/分位数与分布代数。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Gaussian {
    mean: f64,
    variance: f64,
    standard_deviation: f64,
}

impl Gaussian {
    /// 构造正态分布;`variance <= 0` 时 panic(与 Go 版一致)。
    pub fn new(mean: f64, variance: f64) -> Self {
        assert!(variance > 0.0, "variance must be positive");
        Gaussian {
            mean,
            variance,
            standard_deviation: variance.sqrt(),
        }
    }

    fn from_precision_mean(precision: f64, precision_mean: f64) -> Self {
        Gaussian::new(precision_mean / precision, 1.0 / precision)
    }

    /// 概率密度函数 pdf(x)。
    pub fn pdf(&self, x: f64) -> f64 {
        let m = self.standard_deviation * (2.0 * std::f64::consts::PI).sqrt();
        let e = (-(x - self.mean).powi(2) / (2.0 * self.variance)).exp();
        e / m
    }

    /// 累积分布函数 cdf(x)。
    pub fn cdf(&self, x: f64) -> f64 {
        0.5 * erfc(-(x - self.mean) / (self.standard_deviation * std::f64::consts::SQRT_2))
    }

    /// 分位数函数 ppf(x),即 cdf 的反函数。
    pub fn ppf(&self, x: f64) -> f64 {
        self.mean - self.standard_deviation * std::f64::consts::SQRT_2 * ierfc(2.0 * x)
    }

    /// 分布相加:独立随机变量之和。
    pub fn add(&self, d: &Gaussian) -> Gaussian {
        Gaussian::new(self.mean + d.mean, self.variance + d.variance)
    }

    /// 分布相减。
    pub fn sub(&self, d: &Gaussian) -> Gaussian {
        Gaussian::new(self.mean - d.mean, self.variance + d.variance)
    }

    /// 常数缩放。
    pub fn scale(&self, c: f64) -> Gaussian {
        Gaussian::new(self.mean * c, self.variance * c * c)
    }

    /// 精度加权乘积分布(贝叶斯更新)。
    pub fn mul(&self, d: &Gaussian) -> Gaussian {
        let precision = 1.0 / self.variance;
        let dprecision = 1.0 / d.variance;
        Gaussian::from_precision_mean(
            precision + dprecision,
            precision * self.mean + dprecision * d.mean,
        )
    }

    /// 精度加权商分布。
    pub fn div(&self, d: &Gaussian) -> Gaussian {
        let precision = 1.0 / self.variance;
        let dprecision = 1.0 / d.variance;
        Gaussian::from_precision_mean(
            precision - dprecision,
            precision * self.mean - dprecision * d.mean,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        assert_eq!(sign(-5i32), -1);
        assert_eq!(sign(0i32), 0);
        assert_eq!(sign(7i32), 1);
        assert_eq!(sign(-1.5f64), -1.0);
        assert_eq!(sign(2.5f64), 1.0);
    }

    #[test]
    fn test_stats() {
        let nums = [1.0, 2.0, 3.0, 4.0];
        let m = mean(&nums);
        assert!((m - 2.5).abs() < 1e-9);
        let v = variance(m, &nums);
        assert!((v - 1.25).abs() < 1e-9);
        assert!((standard_deviation(&nums) - 1.25f64.sqrt()).abs() < 1e-9);
    }

    #[test]
    fn test_erfc() {
        // 与标准值对照:erfc(0)=1, erfc(1)≈0.1573, erfc(2)≈0.00468
        assert!((erfc(0.0) - 1.0).abs() < 1e-6);
        assert!((erfc(1.0) - 0.1572992).abs() < 1e-6);
        assert!((erfc(2.0) - 0.0046777).abs() < 1e-6);
    }

    #[test]
    fn test_gaussian() {
        let g = Gaussian::new(2.0, 9.0);
        // pdf 在均值处取峰值
        let peak = g.pdf(2.0);
        assert!(
            peak > 0.0 && (peak - 1.0 / (3.0 * (2.0 * std::f64::consts::PI).sqrt())).abs() < 1e-9
        );
        // cdf(均值)=0.5
        assert!((g.cdf(2.0) - 0.5).abs() < 1e-6);
        // ppf 是 cdf 的反函数
        assert!((g.ppf(0.5) - 2.0).abs() < 1e-4);
        let p = g.ppf(0.975);
        let back = g.cdf(p);
        assert!((back - 0.975).abs() < 1e-4);
        // 分布代数
        let a = Gaussian::new(0.0, 1.0);
        let b = Gaussian::new(1.0, 4.0);
        assert_eq!(a.add(&b), Gaussian::new(1.0, 5.0));
        assert_eq!(a.sub(&b), Gaussian::new(-1.0, 5.0));
        assert_eq!(a.scale(3.0), Gaussian::new(0.0, 9.0));
    }

    #[test]
    #[should_panic]
    fn test_gaussian_zero_variance_panics() {
        Gaussian::new(0.0, 0.0);
    }
}
