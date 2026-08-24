import { useEffect, useMemo, useState } from "react";

function wsUrl() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}/ws/logs`;
}

function dateText(value) {
  return value ? new Date(value).toLocaleString("ar-JO") : "—";
}

export default function App() {
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState("connecting");

  useEffect(() => {
    let socket;
    let timer;
    let stopped = false;

    fetch("/api/logs/recent?limit=100")
      .then((response) => response.json())
      .then(setLogs)
      .catch(() => undefined);

    function connect() {
      if (stopped) return;
      socket = new WebSocket(wsUrl());
      setStatus("connecting");

      socket.onopen = () => setStatus("connected");
      socket.onclose = () => {
        setStatus("disconnected");
        if (!stopped) timer = setTimeout(connect, 3000);
      };
      socket.onerror = () => setStatus("error");

      socket.onmessage = (message) => {
        const payload = JSON.parse(message.data);

        if (payload.event === "new_log") {
          setLogs((current) => [
            payload.data,
            ...current.filter((item) => item.id !== payload.data.id),
          ].slice(0, 200));
        }

        if (payload.event === "threat_alert") {
          setAlerts((current) => [payload.data, ...current].slice(0, 20));
        }
      };
    }

    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      socket?.close();
    };
  }, []);

  const severityCounts = useMemo(() => {
    const result = { low: 0, medium: 0, high: 0, critical: 0 };
    logs.forEach((log) => {
      const key = String(log.severity || "low").toLowerCase();
      if (key in result) result[key] += 1;
    });
    return result;
  }, [logs]);

  return (
    <main className="container">
      <header className="header">
        <div>
          <p className="eyebrow">REAL-TIME MONITORING</p>
          <h1>لوحة استخبارات التهديدات</h1>
          <p className="subtitle">السجلات والتنبيهات في الوقت الحقيقي</p>
        </div>
        <div className={`status ${status}`}>● {status}</div>
      </header>

      <section className="cards">
        <div><span>السجلات</span><strong>{logs.length}</strong></div>
        <div><span>منخفض</span><strong>{severityCounts.low}</strong></div>
        <div><span>متوسط</span><strong>{severityCounts.medium}</strong></div>
        <div><span>مرتفع أو حرج</span><strong>{severityCounts.high + severityCounts.critical}</strong></div>
      </section>

      <section className="panel">
        <h2>السجلات الحديثة</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>الوقت</th>
                <th>IP المصدر</th>
                <th>IP الوجهة</th>
                <th>الحدث</th>
                <th>الخطورة</th>
                <th>النص الأصلي</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr><td colSpan="6" className="empty">لا توجد سجلات</td></tr>
              ) : logs.map((log) => (
                <tr key={log.id}>
                  <td>{dateText(log.timestamp)}</td>
                  <td className="mono">{log.source_ip || "—"}</td>
                  <td className="mono">{log.destination_ip || "—"}</td>
                  <td>{log.event_type}</td>
                  <td><span className={`badge ${log.severity}`}>{log.severity}</span></td>
                  <td className="message">{log.raw_message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h2>التنبيهات اللحظية</h2>
        {alerts.length === 0 ? (
          <p className="empty">لم تصل تنبيهات بعد.</p>
        ) : alerts.map((alert, index) => (
          <article className="alert" key={`${alert.id}-${index}`}>
            <strong>{alert.threat_type}</strong>
            <span> الدرجة: {alert.threat_score}</span>
            <p>{alert.description}</p>
          </article>
        ))}
      </section>
    </main>
  );
}
