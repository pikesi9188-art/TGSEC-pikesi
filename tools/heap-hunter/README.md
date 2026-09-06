# 蓝鸟猎手（JDumpSpider）

授权离线拆 heapdump。JAR 是 wanghw `JDumpSpider 1.1-SNAPSHOT`，外挂 `HunterLauncher -batch`。

入口不要直接 `java -jar`。统一走：

```bash
python3 炼蛊房/heap_cred_scan.py <dump.hprof> --out exports/.../接管/heap_creds/
python3 炼蛊房/heap_cred_scan.py spider --dump <dump.hprof> --out ...
python3 炼蛊房/heap_cred_scan.py batch --dir <含hprof的目录> --out ...
python3 炼蛊房/heap_cred_scan.py from-probe --probe <probe.json> \
  --dump-dir <测绘/heapdump> --out <接管/heap_creds> --case <案>
```

默认：字节正则（本库补的类名/键）+ 有 Java 时再跑对象图蜘蛛。不要加 `export-strings`。

`HunterLauncher` 是蓝鸟后加的壳，class file 70（要 Java 26）。本库 `batch` **不调它**，对每份堆走 `Main`（JDK 8/17 即可）。
