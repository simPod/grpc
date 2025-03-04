# gRPC Bazel BUILD file.
#
# Copyright 2022 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load(
    "//bazel:grpc_build_system.bzl",
    "grpc_cc_library",
)

licenses(["reciprocal"])

package(
    default_visibility = ["//visibility:public"],
    features = [
        "layering_check",
    ],
)

grpc_cc_library(
    name = "observability",
    srcs = [
        "observability.cc",
    ],
    hdrs = [
        "//:include/grpcpp/ext/gcp_observability.h",
    ],
    external_deps = [
        "absl/status",
        "absl/status:statusor",
        "absl/types:optional",
        "googleapis_monitoring_grpc_service",
        "googleapis_trace_grpc_service",
        "opencensus-stats",
        "opencensus-stats-stackdriver_exporter",
        "opencensus-trace",
        "opencensus-trace-stackdriver_exporter",
    ],
    language = "c++",
    visibility = ["//:__subpackages__"],
    deps = [
        "observability_config",
        "//:gpr",
        "//:grpc++",
        "//:grpc_opencensus_plugin",
    ],
)

grpc_cc_library(
    name = "observability_config",
    srcs = [
        "observability_config.cc",
    ],
    hdrs = [
        "observability_config.h",
    ],
    external_deps = [
        "absl/status",
        "absl/status:statusor",
        "absl/strings",
        "absl/types:optional",
    ],
    language = "c++",
    visibility = ["//test:__subpackages__"],
    deps = [
        "//:gpr",
        "//:grpc_base",
        "//:grpc_public_hdrs",
        "//src/core:env",
        "//src/core:error",
        "//src/core:json",
        "//src/core:json_args",
        "//src/core:json_object_loader",
        "//src/core:slice",
        "//src/core:slice_refcount",
        "//src/core:status_helper",
        "//src/core:validation_errors",
    ],
)

grpc_cc_library(
    name = "observability_logging_sink",
    srcs = [
        "observability_logging_sink.cc",
    ],
    hdrs = [
        "observability_logging_sink.h",
    ],
    external_deps = [
        "absl/strings",
        "absl/strings:str_format",
        "absl/types:optional",
        "googleapis_logging_grpc_service",
        "protobuf_headers",
    ],
    language = "c++",
    visibility = ["//test:__subpackages__"],
    deps = [
        "observability_config",
        "//:gpr_platform",
        "//:grpc++",
        "//:grpc_opencensus_plugin",
        "//src/core:env",
        "//src/cpp/ext/filters/logging:logging_sink",
    ],
)
