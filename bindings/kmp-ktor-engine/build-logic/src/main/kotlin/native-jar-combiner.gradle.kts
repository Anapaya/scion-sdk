// Copyright 2026 Anapaya Systems

/*
 * Copies the native libraries of a Gobley module into the main JVM jar.
 *
 * Gobley packages each JVM library in a jar of its own, with the JNA prefix
 * of the platform as classifier. That is its documented design: the consumer
 * adds the jar for its platform by classifier. A copy in the main jar lets a
 * consumer depend on the module alone.
 */

// Sync, so a library that the build stops staging leaves the jar.
val stage = tasks.register<Sync>("stageJvmNativeLibrary") {
    group = "build"
    into(layout.buildDirectory.dir("jvmNativeResources"))

    // Gobley puts each library at its JNA path, in one jar per target.
    // The jar also holds a manifest under that path.
    NativeTarget.jvmTargets.forEach { target ->
        val jar = tasks.named<AbstractArchiveTask>("jarJvmRustRuntime${target.gobleyTarget}Release")
        from(jar.flatMap { it.archiveFile }.map { zipTree(it) }) { exclude("**/META-INF/**") }
    }
}

tasks.withType<ProcessResources>().matching { it.name == "jvmProcessResources" }.configureEach {
    from(stage)
}
