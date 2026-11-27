import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";

const CHART_COLORS = ["#ff4655", "#ffb547", "#26c9eb", "#7d8cff"];

function PieVisualization({ data }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="52%" innerRadius={45} outerRadius={65} paddingAngle={3} stroke="none">
          {data.map((item, index) => <Cell key={item.name} fill={CHART_COLORS[index % CHART_COLORS.length]} />)}
        </Pie>
        <Tooltip contentStyle={{ background: "#111827", border: "1px solid #253344", borderRadius: 8, color: "#e8f0f8", fontSize: 11 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

function AreaVisualization({ data }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ left: -20, right: 12, top: 12 }}>
        <defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#00bfff" stopOpacity={0.28} /><stop offset="100%" stopColor="#00bfff" stopOpacity={0} /></linearGradient></defs>
        <CartesianGrid stroke="#1f2b39" strokeDasharray="3 4" vertical={false} />
        <XAxis dataKey="scan" tick={{ fill: "#627184", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis domain={[0, 100]} tick={{ fill: "#627184", fontSize: 10 }} axisLine={false} tickLine={false} />
        <Tooltip contentStyle={{ background: "#111827", border: "1px solid #253344", borderRadius: 8, color: "#e8f0f8", fontSize: 11 }} />
        <Area type="monotone" dataKey="risk" stroke="#00bfff" strokeWidth={2} fill="url(#riskFill)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export default function ChartVisualization({ type, data }) {
  return type === "pie" ? <PieVisualization data={data} /> : <AreaVisualization data={data} />;
}
