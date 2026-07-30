import { useRef, useMemo, useState, useEffect } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { ThreatTelemetry } from "@/hooks/useRealtimeThreats";

// Utility to convert Lat/Lng to 3D Cartesian coordinates
export function latLngToVector3(lat: number, lng: number, radius: number): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lng + 180) * (Math.PI / 180);
  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);
  return new THREE.Vector3(x, y, z);
}

// Fixed global hubs for simulated origins if threat data lacks source
const CYBER_HUBS = [
  { lat: 55.75, lng: 37.62 },   // Moscow
  { lat: 39.90, lng: 116.40 },  // Beijing
  { lat: 40.71, lng: -74.01 },  // New York
  { lat: 51.51, lng: -0.13 },   // London
  { lat: 35.68, lng: 139.69 },  // Tokyo
];

interface ArcProps {
  threat: ThreatTelemetry;
  radius: number;
  onComplete: (id: string) => void;
}

function ThreatArc({ threat, radius, onComplete }: ArcProps) {
  const particleRef = useRef<THREE.Mesh>(null);
  const rippleRef = useRef<THREE.Mesh>(null);
  
  // Animation state
  const [progress, setProgress] = useState(0);
  const duration = 2.0; // seconds for particle to travel
  const rippleDuration = 1.5;

  // Calculate coordinates
  const { curve, color, targetPos } = useMemo(() => {
    // Generate a pseudo-random source hub based on the threat ID or domain length
    const hubIndex = threat.domain.length % CYBER_HUBS.length;
    const sourceHub = CYBER_HUBS[hubIndex];

    const sourcePos = latLngToVector3(sourceHub.lat, sourceHub.lng, radius);
    
    // Fallback target if missing
    const tLat = threat.latitude ?? (Math.random() * 140 - 70);
    const tLng = threat.longitude ?? (Math.random() * 360 - 180);
    const target = latLngToVector3(tLat, tLng, radius);

    // Midpoint for the arc curve (raise it above the sphere)
    const midPoint = sourcePos.clone().lerp(target, 0.5);
    const distance = sourcePos.distanceTo(target);
    midPoint.normalize().multiplyScalar(radius + distance * 0.3);

    const bezier = new THREE.QuadraticBezierCurve3(sourcePos, midPoint, target);

    // Map threat type to color
    let c = "#00F0FF"; // Default Low/Scan
    const type = threat.threatType.toLowerCase();
    if (type.includes("malware") || type.includes("ransomware")) c = "#FF003C";
    else if (type.includes("phishing")) c = "#FFB800";
    else if (type.includes("botnet") || type.includes("ddos")) c = "#FF6B35";

    return { curve: bezier, color: c, targetPos: target };
  }, [threat, radius]);

  useFrame((state, delta) => {
    if (progress < 1) {
      // Move particle along the curve
      const newProgress = Math.min(progress + delta / duration, 1);
      setProgress(newProgress);

      if (particleRef.current) {
        const point = curve.getPoint(newProgress);
        particleRef.current.position.copy(point);
      }
    } else if (progress < 1 + (rippleDuration / duration)) {
      // Ripple effect phase
      const newProgress = progress + delta / duration;
      setProgress(newProgress);
      
      if (rippleRef.current) {
        rippleRef.current.lookAt(0, 0, 0);
        const ripplePhase = (newProgress - 1) / (rippleDuration / duration);
        rippleRef.current.scale.setScalar(1 + ripplePhase * 2);
        (rippleRef.current.material as THREE.MeshBasicMaterial).opacity = 1 - ripplePhase;
      }
    } else {
      // Done
      onComplete(threat.id);
    }
  });

  return (
    <group>
      {/* Arc Line */}
      <line>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            args={[new Float32Array(curve.getPoints(50).flatMap(p => [p.x, p.y, p.z])), 3]}
            count={50}
            array={new Float32Array(curve.getPoints(50).flatMap(p => [p.x, p.y, p.z]))}
            itemSize={3}
          />
        </bufferGeometry>
        <lineBasicMaterial color={color} transparent opacity={0.15} blending={THREE.AdditiveBlending} />
      </line>

      {/* Moving Particle */}
      {progress < 1 && (
        <mesh ref={particleRef}>
          <sphereGeometry args={[0.02, 8, 8]} />
          <meshBasicMaterial color="#ffffff" />
          {/* Point light to illuminate the globe surface near the particle */}
          <pointLight color={color} intensity={0.5} distance={0.5} />
        </mesh>
      )}

      {/* Impact Ripple */}
      {progress >= 1 && progress < 1 + (rippleDuration / duration) && (
        <mesh ref={rippleRef} position={targetPos}>
          <ringGeometry args={[0.02, 0.04, 32]} />
          <meshBasicMaterial 
            color={color} 
            transparent 
            opacity={1} 
            blending={THREE.AdditiveBlending} 
            side={THREE.DoubleSide} 
          />
        </mesh>
      )}
    </group>
  );
}

export default function ThreatArcs({ threats }: { threats: ThreatTelemetry[] }) {
  const [activeArcs, setActiveArcs] = useState<ThreatTelemetry[]>([]);
  const seenIds = useRef<Set<string>>(new Set());

  // Watch for new threats and add them to active arcs
  useEffect(() => {
    const newThreats = threats.filter(t => !seenIds.current.has(t.id));
    if (newThreats.length > 0) {
      newThreats.forEach(t => seenIds.current.add(t.id));
      setActiveArcs(prev => [...prev, ...newThreats]);
    }
    
    // Prevent memory leaks from keeping too many IDs
    if (seenIds.current.size > 1000) {
      const array = Array.from(seenIds.current);
      seenIds.current = new Set(array.slice(array.length - 500));
    }
  }, [threats]);

  const handleArcComplete = (id: string) => {
    setActiveArcs(prev => prev.filter(t => t.id !== id));
  };

  return (
    <group>
      {activeArcs.map(threat => (
        <ThreatArc 
          key={threat.id} 
          threat={threat} 
          radius={2.0} 
          onComplete={handleArcComplete} 
        />
      ))}
    </group>
  );
}
