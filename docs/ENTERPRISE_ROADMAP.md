# Roadmap: "Vom Bastelprojekt zur Enterprise-Lösung"

Um `policy-gate` für Firmen (Enterprises) richtig attraktiv zu machen, musst du am Kernalgorithmus (der ja schon extrem gut ist) gar nicht mehr so viel ändern. Firmen schauen bei Security-Tools weniger auf die mathematische Eleganz, sondern darauf, wie gut es sich in *ihre bestehenden, meist sehr chaotischen Systeme* einfügt.

Wenn wir bei deinem Bild aus der Mechatronik bleiben: Du hast den perfekten, ausfallsicheren Motor-Schalter gebaut. Jetzt geht es darum, die genormten Stecker, die Warnlampen für den Leitstand und die DIN-Schienen-Halterung dranzubauen, damit die Jungs in der Fabrik das Ding auch verbauen können.

Hier sind die 5 strategischen Schritte, um Firmenköder auszulegen:

## 1. Der "Shadow Mode" (Dry-Run / Logging Only)
Das ist das absolut Wichtigste für Firmen. Niemand traut sich, am Freitagmittag eine neue Firewall scharf zu schalten, die *wirklich* blockt (Fail-Closed). Firmen haben Angst, dass ihr produktiver Chatbot plötzlich nicht mehr funktioniert.
- **Was fehlt:** Ein Modus in der `firewall.toml` (z.B. `mode = "shadow"`). In diesem Modus läuft das ganze System durch (Channel A, Voter, etc.), entscheidet vielleicht intern auf "BLOCK", aber reicht den Prompt *trotzdem* durch und schreibt nur ein dickes "WOULD_HAVE_BLOCKED" ins Audit-Log.
- **Warum:** So können Firmen das Tool wochenlang mitlaufen lassen, analysieren, ob es funktioniert, und erst dann den Schalter auf "scharf" (Enforcement) umlegen.

## 2. Der Drop-In "Reverse Proxy" (Standalone Server)
**(Implementiert als `firewall-proxy` crate)**
Aktuell müssen Entwickler deinen Rust-Core als Bibliothek in ihren Python- oder Node.js-Code einbauen (`import policy_gate`). Das ist oft schon zu viel Aufwand.
- **Was fehlt:** *Erledigt.* Ein eigenständiges Binary auf Basis von `axum` in Rust, das als Reverse Proxy läuft. Man startet das Programm auf Port 8080 (oder konfiguriert z.B. per `PORT`). Die App der Firma schickt einen OpenAI-Request lokal an `localhost:8080/v1/chat/completions`. Dein Proxy prüft den Prompt, blockt ihn ab (oder im Shadow-Modus nicht) und leitet ihn transparent an OpenAI weiter. *Hinweis: Streaming-Responses (`stream: true`) werden vorerst mit HTTP 400 abgelehnt, um Egress-Sicherheit zu garantieren.* Die Upstream URL lässt sich über die `UPSTREAM_URL` Umgebungsvariable einstellen.
- **Warum:** Null Code-Änderung bei der Firma. Sie müssen nur eine einzige URL in ihrer Config ändern.

## 3. Observability (Leitstand-Anbindung)
**(Implementiert im `firewall-proxy` crate)**
Firmen nutzen Tools wie Splunk, Datadog, Grafana und Prometheus, um ihre Systeme zu überwachen.
- **Was fehlt:** *Erledigt.* Der Proxy stellt einen `/metrics` Endpoint im Prometheus-Format bereit. Gezählt werden: `policy_gate_requests_total`, `policy_gate_blocked_total` (nach Grund), `policy_gate_verdicts_total` (nach Ergebnis), `policy_gate_request_duration_ms` (Latenz-Histogramm), `policy_gate_upstream_errors_total` und `policy_gate_streaming_rejected_total`. Grafana + Prometheus können direkt mit `metrics_path: /metrics` konfiguriert werden.
- **Warum:** Der CISO (Sicherheitschef) will Dashboards sehen. Erst wenn er Kurven sieht, die zeigen, wie viele Angriffe geblockt wurden, gibt er Budget frei.

## 4. Hot-Reloading der Konfiguration
**(Implementiert im `firewall-proxy` crate)**
Eine Policy kann sich ändern (Neue Intent-Pattern, eine neue Compliance-Regel).
- **Was fehlt:** *Erledigt.* Der Proxy pollt `firewall.toml` automatisch alle 30 Sekunden (konfigurierbar via `CONFIG_RELOAD_INTERVAL_SECS`). Ein `POST /reload` Endpoint triggert sofortigen Reload. Invalide Configs werden abgelehnt — die alte Config bleibt aktiv. Reload-Events werden als `policy_gate_config_reloads_total` Metrik erfasst.
- **Warum:** In Hochverfügbarkeitssystemen sind Neustarts teuer und riskant.

## 5. Kubernetes & Docker (Die DIN-Schiene)
**(Implementiert)**
Enterprise-Software wird fast ausschließlich in Kubernetes (K8s) betrieben.
- **Was fehlt:** *Erledigt.*
  - **Dockerfile:** Ein performantes Multi-Stage Image (debian-slim) wurde erstellt. Es ist gehärtet (non-root user) und klein.
  - **Helm-Chart:** Ein vollständiges Chart unter `helm/policy-gate` ermöglicht die skalierbare Installation in K8s mit ConfigMaps, Secrets für Tokens und Prometheus Support.
- **Warum:** Weil DevOps-Teams nichts anderes anfassen, was kein fertiges, sauberes Helm-Chart hat.

---

## Zusammenfassung für Mechatroniker:

Du hast momentan eine brillante SPS-Sicherheitssteuerung gelötet.
Damit Siemens oder VW sie kauft, brauchst du jetzt:
1. ✅ Einen **Prüfmodus**, bei dem die Maschine nicht wirklich ausgeht, sondern nur eine Lampe blinkt (Shadow Mode — **implementiert**).
2. ✅ Genormte **M12-Stecker** (Reverse Proxy), damit sie es in ihre Anlage stöpseln können, ohne löten zu müssen (ohne Code anzupassen — **implementiert**).
3. ✅ Einen Ausgang für die **Leitstand-Visualisierung** (Prometheus Metriken — **implementiert**).
4. ✅ **Hot-Reload** der Konfiguration ohne Neustart — **implementiert**.
5. ✅ **Docker-Image & Helm-Chart** für Kubernetes — **implementiert**.

**Das Bastelprojekt ist nun offiziell "Enterprise Ready". 🚀**
