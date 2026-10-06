# ITS Transportation Datasets Guide

This directory contains lightweight development fixtures for the **AI-SecOps V2 Intelligent Transportation System (ITS)** domain layer, alongside configuration guidelines for large-scale external transportation benchmarks.

---

## 1. Local Development Fixtures (Included)

The following JSON files are included in the repository for smoke testing, offline demos, and unit test execution:

| File | Purpose | Contents |
|---|---|---|
| `roads.json` | Road network topology | 8 monitored arterial and highway corridors in Ahmedabad |
| `traffic.json` | Telemetry snapshot | Speed, vehicle flow, and congestion classification levels |
| `incidents.json` | Active incident log | Accidents, road blocks, construction, and traffic jams |

These mock datasets are intentionally small to ensure instant test execution without network or disk dependencies.

---

## 2. Production-Scale Benchmarks (External)

For large-scale evaluation (millions of observations), AI-SecOps V2 supports public transportation datasets via streaming chunk adapters:

### A. PEMS-BAY
- **Source**: Caltrans Performance Measurement System (PeMS) District 4 (San Francisco Bay Area).
- **Scale**: ~16.9M observations across 325 sensor stations.
- **Resolution**: 5-minute intervals spanning 6 months (January 1, 2017 to June 30, 2017).
- **Primary Features**: Traffic speed (mph), flow, occupancy, sensor coordinates.
- **Recommended Local Path**: `datasets/pems-bay/pems-bay.h5` or `datasets/pems-bay/pems-bay.csv`
- **Environment Variable**: `ITS_PEMS_BAY_PATH=/path/to/pems-bay.csv`

### B. METR-LA
- **Source**: Los Angeles County Highway Network (LADOT / PeMS District 7).
- **Scale**: ~6.5M observations across 207 sensor stations.
- **Resolution**: 5-minute intervals spanning 4 months (March 1, 2012 to June 27, 2012).
- **Primary Features**: Traffic speed (mph), flow, occupancy.
- **Recommended Local Path**: `datasets/metr-la/metr-la.h5` or `datasets/metr-la/metr-la.csv`
- **Environment Variable**: `ITS_METR_LA_PATH=/path/to/metr-la.csv`

### C. Caltrans PeMS03 / PeMS04 / PeMS07 / PeMS08
- Multi-month highway traffic flow benchmarks (300+ sensors, 5-minute intervals).

### D. NYC TLC Trip Records
- High-volume trip records (pickup/dropoff zones, distances, durations) in Parquet format.
- **Environment Variable**: `ITS_PARQUET_PATH=/path/to/yellow_tripdata.parquet`

---

## 3. Streaming and Memory Protection

**IMPORTANT**: Multi-gigabyte raw datasets are **NOT** committed to Git.

When real dataset files are placed locally:
1. Loaders process records in configurable chunks (default: `1000` rows per chunk via `ITS_CHUNK_SIZE`).
2. Generators stream observations directly through the validation and context layer without loading entire datasets into RAM.
3. If no external file path is set, the `PEMSAdapter` operates in generator mode to simulate realistic diurnal speed and flow cycles matching the exact sensor topology.

---

## 4. Running the Adapters

Run with default JSON mock data:
```bash
python -m its.demo
```

Run with PEMS-BAY adapter:
```bash
python -m its.demo --dataset pems-bay --query "What is the traffic condition on US-101 S?"
```

Run with METR-LA adapter:
```bash
python -m its.demo --dataset metr-la --query "What is the traffic condition on I-5 N?"
```
