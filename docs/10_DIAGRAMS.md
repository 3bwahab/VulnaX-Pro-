# 10 — Mermaid Diagrams & Execution Flows

## 1. System Context

```mermaid
flowchart TB
  U[Security Analyst] -->|python main.py| CLI[CLI / Live Dashboard]
  CLI --> K[Kernel + ScanContext]
  K --> P[Pipeline DAG]
  P --> E[16 Engines]
  E --> ADP[Tool Adapter Layer]
  ADP --> T[(subfinder / naabu / httpx /\n katana / nuclei / wappalyzer ...)]
  E --> ST[(Embedded Store:\nSQLite + Artifacts + Cache)]
  E --> AI[LLM Adapter\nclaude-opus-4-8]
  ST --> R[Reporting Engine]
  R --> OUT[HTML / MD / JSON Reports]
```

## 2. Layered Architecture

```mermaid
flowchart TB
  subgraph Presentation
    CLI[CLI Typer]; DASH[Rich Dashboard]; RND[Report Renderers]
  end
  subgraph Orchestration
    PIPE[Pipeline]; SCHED[Scheduler]; BUS[Event Bus]; SCOPE[Scope Guard]
  end
  subgraph Engines
    direction LR
    DISC[Discovery]; VAL[Validation]; FP[Fingerprint]; TECH[Tech]; CRAWL[Crawl];
    JS[JS Intel]; API[API]; AUTH[AuthMap]; CFG[Config]; CORR[Correlation];
    CVE[CVE]; GRAPH[Surface Graph]; RISK[Risk]; PATH[Attack Path]; AIA[AI]; REP[Report]
  end
  subgraph Intelligence
    PAY[Payload Intel]; CVEI[CVE Data]; RMODEL[Risk Model]
  end
  subgraph Integration
    REG[Adapter Registry]; PROC[Process Runner]; NORM[Normalizers]
  end
  subgraph Kernel
    POOL[Worker Pools]; RL[Rate Limit]; RET[Retry]; CACHE[Cache]; MET[Metrics]
  end
  subgraph Persistence
    SQL[(SQLite)]; ART[(Artifacts)]; CCH[(Cache)]
  end
  Presentation --> Orchestration --> Engines
  Engines --> Intelligence
  Engines --> Integration --> Kernel --> Persistence
```

## 3. Pipeline Stage DAG

```mermaid
flowchart LR
  A[Stage0 Discovery] --> B[Stage1 Validation]
  B --> C[Stage2 Fingerprint]
  B --> D[Stage2 Tech Detection]
  D --> E[Stage3 Deep Crawl]
  E --> F[Stage4 JS Intel]
  E --> G[Stage4 API Discovery]
  E --> H[Stage4 Auth Mapping]
  C --> I[Stage5 CVE Intel]
  D --> I
  D --> J[Stage5 Config Assess]
  C & D & I & J --> K[Stage5 Vuln Correlation]
  F & G & H & K --> L[Stage6 Surface Graph]
  L --> M[Stage6 Risk Scoring]
  M --> N[Stage6 Attack Path]
  N --> O[Stage7 AI Analyst]
  O --> P[Stage8 Reporting]
```

## 4. Execution Flow — End to End

```mermaid
sequenceDiagram
  participant U as User
  participant M as main.py
  participant K as Kernel
  participant P as Pipeline
  participant E as Engine
  participant A as Adapter
  participant S as Store
  participant D as Dashboard
  U->>M: python main.py scan --scope ...
  M->>K: load config + scope, build context
  K->>A: healthcheck_all()
  M->>P: run(ctx)
  loop each stage (topo order)
    P->>E: run(ctx)
    E->>A: run(ToolRequest) [bounded, rate-limited, retried]
    A-->>E: AdapterResult (typed models)
    E->>S: persist models
    E-->>D: emit bus events (counters/progress)
  end
  P->>E: Reporting.run(ctx)
  E->>S: read full bundle
  E-->>U: write reports + print paths
```

## 5. Adapter Reliability Wrapper

```mermaid
flowchart LR
  REQ[ToolRequest] --> RL{Rate limit\ntoken?}
  RL -->|wait| RL
  RL -->|ok| CK{Cache hit?}
  CK -->|yes| OUT[Return cached models]
  CK -->|no| TO[Timeout guard]
  TO --> EX[Process exec\nstream stdout]
  EX -->|fail| RT{Retry left?}
  RT -->|yes backoff| TO
  RT -->|no| ERR[AdapterError]
  EX -->|ok| NM[Normalize raw->models]
  NM --> VAL[Validate schema]
  VAL --> CACHE[(Write cache)]
  CACHE --> OUT
```

## 6. Payload Intelligence Selection Flow

```mermaid
flowchart TB
  TP[Tech Profile] --> SEL[Selector]
  CAT[Resource Catalog\nSecLists+Nuclei] --> SEL
  RUL[rules.yaml weights] --> SEL
  SEL --> SC[Score + budget cap]
  SC --> RES[Selection: wordlists + nuclei tags + actions]
  RES --> CRAWL[DeepCrawler]
  RES --> CORR[VulnCorrelation\nNuclei tag filter]
  RES --> CFG[ConfigAssessment\nsensitive files]
```

## 7. Attack Path Synthesis

```mermaid
flowchart LR
  MODELS[All typed models] --> GRAPH[Surface Graph]
  FIND[Findings] --> OVL[Overlay on graph]
  GRAPH --> OVL
  OVL --> ENTRY[Identify entry points]
  OVL --> TGT[Identify targets]
  ENTRY & TGT --> SRCH[Capability-rule traversal]
  SRCH --> TOPK[Top-K paths]
  TOPK --> SCORE[Score likelihood×impact]
  SCORE --> NARR[Narratives]
  SCORE --> BOOST[Chain boost -> RiskScoring]
```

## 8. Concurrency Model

```mermaid
flowchart TB
  SCHED[Adaptive Scheduler] --> DNSP[DNS pool]
  SCHED --> HTTPP[HTTP pool]
  SCHED --> PROCP[Process pool]
  SCHED --> CPUP[CPU pool]
  DNSP & HTTPP --> RLG[Global + per-host token buckets]
  RLG --> WORK[Bounded async workers]
  WORK --> ADP[Adapters]
  WORK -. AIMD feedback (latency/errors) .-> SCHED
```

## 9. Data Model Relationships (ER-style)

```mermaid
erDiagram
  ASSET ||--o{ SERVICE : runs
  ASSET ||--o{ TECHNOLOGY : uses
  ASSET ||--o{ ENDPOINT : serves
  ASSET ||--o{ AUTHSURFACE : has
  ENDPOINT ||--o{ JSASSET : includes
  ENDPOINT ||--o{ APIENDPOINT : is
  TECHNOLOGY ||--o{ CVEMATCH : vulnerable
  ENDPOINT ||--o{ FINDING : has
  FINDING ||--|{ EVIDENCE : supported_by
  FINDING ||--o{ RISK : scored
  FINDING }o--o{ ATTACKPATH : participates
```
