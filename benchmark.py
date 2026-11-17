"""Benchmark toy ring-BFV PSI against a non-private set-intersection baseline."""
import argparse, csv, json, platform, statistics, time
from pathlib import Path
from src.bfv_demo import SMALL,LARGE,run_psi,plaintext_baseline

def dataset(cfg):
    # Distinct synthetic US numbers; fixed membership positions, no real contacts.
    server=[f'+1202555{i:04d}' for i in range(cfg.max_server)]
    client=[server[i] for i in range(0,cfg.max_clients,2)]+[
       f'+1310555{i:04d}' for i in range(cfg.max_clients//2)]
    return client,server

def benchmark(repetitions=10,output='results'):
    Path(output).mkdir(parents=True,exist_ok=True)
    records=[]
    for cfg in [SMALL,LARGE]:
        client,server=dataset(cfg)
        expected=plaintext_baseline(client,server)
        # One unmeasured warmup. Regenerates keys every measured trial.
        got,_=run_psi(client,server,cfg)
        assert got==expected,(cfg,got,expected)
        for i in range(repetitions):
            t0=time.perf_counter(); truth=plaintext_baseline(client,server)
            baseline_s=time.perf_counter()-t0
            got,stats=run_psi(client,server,cfg)
            if got!=truth: raise AssertionError(f'Intersection incorrect: {cfg.name}')
            records.append({'iteration':i+1,'baseline_s':baseline_s,'correct':True,**stats})
        print(cfg.name, 'runs=',repetitions,'median total_s=',round(statistics.median(
            x['total_s'] for x in records if x['setting']==cfg.name),5))
    path=Path(output)
    with (path/'bfv_measurements.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(records[0]));writer.writeheader();writer.writerows(records)
    with (path/'bfv_measurements.json').open('w') as f:
        json.dump({'environment':{'python':platform.python_version(),'platform':platform.platform(),
          'processor':platform.processor()},'parameters':'small N=16/32, q=2^120-17, t=65537, toy/non-secure',
          'measurements':records},f,indent=2)
    return records

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repetitions',type=int,default=10)
    p.add_argument('--output',default='results'); a=p.parse_args()
    benchmark(a.repetitions,a.output)
