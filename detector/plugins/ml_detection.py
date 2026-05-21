"""ML 深度学习检测插件 – 包装 detector/ml_detector 的 ML 增强检测功能."""

from __future__ import annotations

from typing import Any

# 尝试导入 ML 检测器
try:
    from detector.ml_detector import detect_with_ml, get_ml_status
    HAS_ML_DETECTOR = True
except ImportError:
    HAS_ML_DETECTOR = False
    detect_with_ml = None
    get_ml_status = None


def run(file_path: str) -> list[dict[str, Any]]:
    """执行 ML 深度学习检测，返回标准 finding 列表.

    注意：只有在真实 ML 模型可用时才进行检测，
    避免使用 pattern-based fallback 产生误报。

    Parameters
    ----------
    file_path: 要检测的文件路径

    Returns
    -------
    list[dict[str, Any]]: 漏洞发现列表，每个 finding 包含 engine="ml" 标记
    """
    if not HAS_ML_DETECTOR or detect_with_ml is None:
        return []

    # 只有在真实 ML 模型可用时才进行检测
    if not is_real_ml_available():
        return []

    try:
        ml_findings = detect_with_ml(file_path)
        for ml_f in ml_findings:
            ml_f["engine"] = ml_f.get("ml_source", "ml")
            ml_f["detector"] = "ml_detection"
            if "engines" not in ml_f:
                ml_f["engines"] = [ml_f["engine"]]
        return ml_findings
    except Exception:
        return []


def get_status() -> dict[str, Any]:
    """获取 ML 检测器状态信息.

    Returns
    -------
    dict[str, Any]: 包含可用性、模型信息等状态
    """
    if not HAS_ML_DETECTOR or get_ml_status is None:
        return {
            "available": False,
            "reason": "ML detector not installed",
        }
    try:
        return get_ml_status()
    except Exception as e:
        return {
            "available": False,
            "reason": str(e),
        }


def is_available() -> bool:
    """检查 ML 检测器是否可用."""
    return HAS_ML_DETECTOR and get_status().get("available", False)


def is_real_ml_available() -> bool:
    """检查真实 ML 模型是否已加载（而非 fallback 模式）."""
    if not HAS_ML_DETECTOR or get_ml_status is None:
        return False
    try:
        status = get_ml_status()
        return status.get("available", False) and status.get("model_loaded", False)
    except Exception:
        return False
