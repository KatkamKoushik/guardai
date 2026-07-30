"use client";

import { useRef, useMemo, useCallback } from "react";
import { Canvas, useFrame, ThreeEvent } from "@react-three/fiber";
import * as THREE from "three";

const PARTICLE_COUNT = 15000;

const vertexShader = `
  uniform float uTime;
  uniform vec2 uMouse;
  uniform float uMouseStrength;
  
  attribute float aScale;
  attribute float aRandom;
  
  varying float vAlpha;
  varying float vDistance;
  
  void main() {
    vec3 pos = position;
    
    float dist = length(pos.xy - uMouse);
    float influence = uMouseStrength / (dist * 0.5 + 0.5);
    influence = clamp(influence, 0.0, 1.0);
    
    pos.xy += normalize(pos.xy - uMouse) * influence * 0.3;
    pos.z += sin(uTime * 0.5 + pos.x * 0.5 + pos.y * 0.5) * 0.15;
    pos.z += cos(uTime * 0.3 + aRandom * 6.28) * 0.1;
    
    vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
    
    vAlpha = 0.3 + influence * 0.7;
    vDistance = length(pos.xy);
    
    gl_PointSize = aScale * (1.0 / -mvPosition.z) * 80.0;
    gl_Position = projectionMatrix * mvPosition;
  }
`;

const fragmentShader = `
  uniform float uTime;
  uniform vec3 uColor1;
  uniform vec3 uColor2;
  uniform vec3 uMouseColor;
  
  varying float vAlpha;
  varying float vDistance;
  
  void main() {
    float dist = length(gl_PointCoord - vec2(0.5));
    if (dist > 0.5) discard;
    
    float strength = 1.0 - (dist * 2.0);
    strength = pow(strength, 2.0);
    
    vec3 color = mix(uColor1, uColor2, vDistance * 0.3);
    color = mix(color, uMouseColor, vAlpha * 0.5);
    
    float pulse = sin(uTime * 2.0 + vDistance * 0.5) * 0.1 + 0.9;
    
    gl_FragColor = vec4(color, strength * vAlpha * pulse * 0.6);
  }
`;

function Particles() {
  const pointsRef = useRef<THREE.Points>(null);
  const mouseRef = useRef(new THREE.Vector2(0, 0));
  const targetMouseRef = useRef(new THREE.Vector2(0, 0));

  const { positions, scales, randoms } = useMemo(() => {
    const positions = new Float32Array(PARTICLE_COUNT * 3);
    const scales = new Float32Array(PARTICLE_COUNT);
    const randoms = new Float32Array(PARTICLE_COUNT);

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const i3 = i * 3;
      const radius = 5 + Math.random() * 10;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);

      positions[i3] = radius * Math.sin(phi) * Math.cos(theta);
      positions[i3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
      positions[i3 + 2] = (Math.random() - 0.5) * 4;

      scales[i] = Math.random() * 0.5 + 0.1;
      randoms[i] = Math.random();
    }

    return { positions, scales, randoms };
  }, []);

  const uniforms = useMemo(
    () => ({
      uTime: { value: 0 },
      uMouse: { value: new THREE.Vector2(0, 0) },
      uMouseStrength: { value: 0 },
      uColor1: { value: new THREE.Color("#00F0FF") },
      uColor2: { value: new THREE.Color("#00FF66") },
      uMouseColor: { value: new THREE.Color("#ffffff") },
    }),
    []
  );

  const handlePointerMove = useCallback((e: ThreeEvent<PointerEvent>) => {
    targetMouseRef.current.set(
      (e.point.x / 10) * 2,
      (e.point.y / 10) * 2
    );
  }, []);

  useFrame((state) => {
    if (!pointsRef.current) return;

    uniforms.uTime.value = state.clock.elapsedTime;

    mouseRef.current.lerp(targetMouseRef.current, 0.1);
    uniforms.uMouse.value.copy(mouseRef.current);

    const targetStrength =
      targetMouseRef.current.length() > 0.01 ? 1.5 : 0;
    uniforms.uMouseStrength.value += (targetStrength - uniforms.uMouseStrength.value) * 0.1;

    pointsRef.current.rotation.z = state.clock.elapsedTime * 0.02;
  });

  return (
    <points ref={pointsRef} onPointerMove={handlePointerMove}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          args={[positions, 3]}
          count={PARTICLE_COUNT}
          array={positions}
          itemSize={3}
        />
        <bufferAttribute
          attach="attributes-aScale"
          args={[scales, 1]}
          count={PARTICLE_COUNT}
          array={scales}
          itemSize={1}
        />
        <bufferAttribute
          attach="attributes-aRandom"
          args={[randoms, 1]}
          count={PARTICLE_COUNT}
          array={randoms}
          itemSize={1}
        />
      </bufferGeometry>
      <shaderMaterial
        vertexShader={vertexShader}
        fragmentShader={fragmentShader}
        uniforms={uniforms}
        transparent
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  );
}

export default function ShaderBackground() {
  return (
    <div className="fixed inset-0 z-0">
      <Canvas
        camera={{ position: [0, 0, 8], fov: 60 }}
        dpr={[1, 1.5]}
        gl={{
          antialias: false,
          alpha: true,
          powerPreference: "high-performance",
        }}
        style={{ background: "transparent" }}
      >
        <Particles />
      </Canvas>
      <div className="absolute inset-0 bg-gradient-to-b from-[#050505]/80 via-transparent to-[#050505]/90 pointer-events-none" />
    </div>
  );
}
