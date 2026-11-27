import { CircleMarker, MapContainer, TileLayer, Tooltip } from "react-leaflet";
import { MapPin } from "lucide-react";
import "leaflet/dist/leaflet.css";

export default function MapPanel({ hosting }) {
  const coordinates = hosting?.coordinates;
  if (!coordinates || coordinates.length !== 2 || !coordinates.every(Number.isFinite)) {
    return <div className="map-empty"><MapPin size={22} /><strong>Location unavailable</strong><span>Public IP geolocation was not returned.</span></div>;
  }
  return (
    <div className="map-frame">
      <MapContainer center={coordinates} zoom={5} scrollWheelZoom={false} className="world-map">
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <CircleMarker center={coordinates} radius={9} pathOptions={{ color: "#00bfff", fillColor: "#00bfff", fillOpacity: 0.8, weight: 2 }}>
          <Tooltip>{[hosting.city, hosting.region, hosting.country].filter(Boolean).join(", ") || "Approximate IP location"}</Tooltip>
        </CircleMarker>
      </MapContainer>
      <div className="map-disclosure"><MapPin size={10} /> Approximate IP geolocation · OpenStreetMap</div>
    </div>
  );
}
