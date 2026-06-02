from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pcaa_core import write_table, run_algorithm_trace
if __name__ == '__main__':
    write_table('latency')
    run_algorithm_trace()
