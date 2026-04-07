"""
SecureGuard AI Module
"""

from .ml_detector import MLDetector
from .behavior_analyzer import BehaviorAnalyzer

__all__ = ['MLDetector', 'BehaviorAnalyzer']


def test():
    print(MLDetector, BehaviorAnalyzer)
