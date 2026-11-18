---
title: Kotlin Multiplatform
description: A Ktor engine that sends HTTP over SCION, for Android, iOS, and the JVM.
---

import DocCardList from '@theme/DocCardList';

[Ktor](https://ktor.io/) is a Kotlin framework from JetBrains for asynchronous HTTP clients and
servers. [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) shares one Kotlin
code base between Android, iOS, desktop, and server apps.

The SCION SDK has `ScionHttp`, a Ktor engine that sends HTTP over SCION. An app keeps its Ktor code,
and only changes the engine. The same engine runs on Android, on iOS, and on the JVM. Maven Central
has it as `net.anapaya.scion:ktor-client-scion`.

<DocCardList />
