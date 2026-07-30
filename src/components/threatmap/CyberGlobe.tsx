import { useRef, useMemo } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { createNoise3D } from "simplex-noise";

const noise3D = createNoise3D();

export default function CyberGlobe() {
  const globeRef = useRef<THREE.Group>(null);
  const atmosphereRef = useRef<THREE.Mesh>(null);

  // Generate continent points using Fibonacci sphere + Simplex Noise
  const { positions, colors } = useMemo(() => {
    const numPoints = 15000;
    const pos = [];
    const col = [];
    const radius = 2.0;

    const phi = Math.PI * (3 - Math.sqrt(5)); // golden angle

    for (let i = 0; i < numPoints; i++) {
      const y = 1 - (i / (numPoints - 1)) * 2; // y goes from 1 to -1
      const r = Math.sqrt(1 - y * y); // radius at y

      const theta = phi * i; // golden angle increment

      const x = Math.cos(theta) * r;
      const z = Math.sin(theta) * r;

      // Use 3D noise to determine if this point is "land" or "water"
      // Multiple octaves for realistic continent shapes
      const noiseVal =
        noise3D(x * 1.5, y * 1.5, z * 1.5) * 0.5 +
        noise3D(x * 3.0, y * 3.0, z * 3.0) * 0.25 +
        noise3D(x * 6.0, y * 6.0, z * 6.0) * 0.125;

      // If noise is above a threshold, it's land
      if (noiseVal > 0.1) {
        pos.push(x * radius, y * radius, z * radius);
        
        // Add a slight color variation based on noise
        const intensity = 0.5 + noiseVal * 0.5;
        col.push(0.0, 0.94 * intensity, 1.0 * intensity); // Cyan base
      } else {
        // Sparse ocean points
        if (Math.random() > 0.98) {
          pos.push(x * radius, y * radius, z * radius);
          col.push(0.0, 0.2, 0.3); // Darker blue/cyan for ocean grid
        }
      }
    }

    return {
      positions: new Float32Array(pos),
      colors: new Float32Array(col),
    };
  }, []);

  const atmosphereShader = useMemo(
    () => ({
      vertexShader: `
        varying vec3 vNormal;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        varying vec3 vNormal;
        void main() {
          float intensity = pow(0.65 - dot(vNormal, vec3(0, 0, 1.0)), 3.0);
          gl_FragColor = vec4(0.0, 0.94, 1.0, 1.0) * intensity;
        }
      `,
      side: THREE.BackSide,
      blending: THREE.AdditiveBlending,
      transparent: true,
      depthWrite: false,
    }),
    []
  );

  useFrame((state) => {
    if (globeRef.current) {
      globeRef.current.rotation.y = state.clock.elapsedTime * 0.05;
    }
  });

  return (
    <group ref={globeRef}>
      {/* Base dark sphere to block points behind the globe */}
      <mesh>
        <sphereGeometry args={[1.98, 64, 64]} />
        <meshBasicMaterial color="#050505" />
      </mesh>

      {/* Continents Point Cloud */}
      <points>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            args={[positions, 3]}
            count={positions.length / 3}
            array={positions}
            itemSize={3}
          />
          <bufferAttribute
            attach="attributes-color"
            args={[colors, 3]}
            count={colors.length / 3}
            array={colors}
            itemSize={3}
          />
        </bufferGeometry>
        <pointsMaterial
          size={0.015}
          vertexColors
          transparent
          opacity={0.8}
          blending={THREE.AdditiveBlending}
        />
      </points>

      {/* Faint Wireframe Sphere */}
      <mesh>
        <sphereGeometry args={[2.01, 32, 32]} />
        <meshBasicMaterial color="#00F0FF" wireframe transparent opacity={0.03} />
      </mesh>

      {/* Atmospheric Halo */}
      <mesh ref={atmosphereRef} scale={1.2}>
        <sphereGeometry args={[2, 64, 64]} />
        <shaderMaterial attach="material" {...atmosphereShader} />
      </mesh>
    </group>
  );
}
