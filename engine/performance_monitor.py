import psutil
import os
from engine.efficiency_optimizer import EfficiencyOptimizer

class PerformanceMonitor:
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.optimizer = EfficiencyOptimizer()
        
    def get_cpu_usage(self) -> float:
        return self.process.cpu_percent(interval=0.1)
    
    def get_memory_usage(self) -> float:
        return self.process.memory_info().rss / (1024 * 1024)
    
    def get_stats(self) -> dict:
        return {
            'cpu_percent': self.get_cpu_usage(),
            'memory_mb': self.get_memory_usage(),
            'threads': self.process.num_threads(),
            'efficiency': self.optimizer.get_efficiency()
        }
