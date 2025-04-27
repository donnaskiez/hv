#pragma once

#include "common.h"

// API documentation configuration
typedef struct _API_DOC_CONFIG {
    BOOLEAN EnableInteractive;
    UINT32 MaxExamples;
    BOOLEAN EnableVersioning;
    CHAR OutputPath[MAX_PATH];
} API_DOC_CONFIG, *PAPI_DOC_CONFIG;

// Testing framework configuration
typedef struct _TEST_CONFIG {
    BOOLEAN EnableCiCd;
    UINT32 TestTimeout;
    BOOLEAN EnableCoverage;
    UINT32 MaxConcurrentTests;
} TEST_CONFIG, *PTEST_CONFIG;

// Benchmark configuration
typedef struct _BENCHMARK_CONFIG {
    UINT32 Duration;
    UINT32 Iterations;
    BOOLEAN EnableProfiling;
    UINT32 WarmupIterations;
} BENCHMARK_CONFIG, *PBENCHMARK_CONFIG;

// Development guidelines configuration
typedef struct _GUIDELINES_CONFIG {
    BOOLEAN EnableStyleCheck;
    BOOLEAN EnableSecurityScan;
    BOOLEAN EnableDocumentationCheck;
    UINT32 MaxLineLength;
} GUIDELINES_CONFIG, *PGUIDELINES_CONFIG;

// SDK configuration
typedef struct _SDK_CONFIG {
    BOOLEAN EnableDebug;
    UINT32 Version;
    CHAR OutputPath[MAX_PATH];
    BOOLEAN EnableSymbols;
} SDK_CONFIG, *PSDK_CONFIG;

// Plugin configuration
typedef struct _PLUGIN_CONFIG {
    UINT32 MaxPlugins;
    BOOLEAN EnableSandbox;
    UINT32 ApiVersion;
    BOOLEAN EnableAutoUpdate;
} PLUGIN_CONFIG, *PPLUGIN_CONFIG;

// Function declarations
NTSTATUS
DevToolsInitialize(
    VOID
);

NTSTATUS
DevToolsConfigureApiDoc(
    PAPI_DOC_CONFIG Config
);

NTSTATUS
DevToolsConfigureTesting(
    PTEST_CONFIG Config
);

NTSTATUS
DevToolsConfigureBenchmark(
    PBENCHMARK_CONFIG Config
);

NTSTATUS
DevToolsConfigureGuidelines(
    PGUIDELINES_CONFIG Config
);

NTSTATUS
DevToolsConfigureSdk(
    PSDK_CONFIG Config
);

NTSTATUS
DevToolsConfigurePlugin(
    PPLUGIN_CONFIG Config
);

NTSTATUS
DevToolsGenerateApiDoc(
    PCHAR OutputPath
);

NTSTATUS
DevToolsRunTests(
    PCHAR TestFilter
);

NTSTATUS
DevToolsRunBenchmark(
    PCHAR BenchmarkName
);

NTSTATUS
DevToolsCheckGuidelines(
    PCHAR FilePath
);

NTSTATUS
DevToolsBuildSdk(
    PSDK_CONFIG Config
);

NTSTATUS
DevToolsInstallPlugin(
    PCHAR PluginPath
);

NTSTATUS
DevToolsUpdatePlugin(
    PCHAR PluginName
);

NTSTATUS
DevToolsVerifyApiCompatibility(
    UINT32 FromVersion,
    UINT32 ToVersion
); 