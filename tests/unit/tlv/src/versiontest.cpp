#include "tlv/version.h"

#include <gtest/gtest.h>

#include <string>

#define OPENTLV_TEST_STRINGIFY_IMPL(value) #value
#define OPENTLV_TEST_STRINGIFY(value) OPENTLV_TEST_STRINGIFY_IMPL(value)

TEST(Unit_TLVVersion, exposes_build_system_version) {
  EXPECT_GE(OPENTLV_VERSION_REVISION, 0);

  const std::string core_version =
      OPENTLV_TEST_STRINGIFY(OPENTLV_VERSION_MAJOR) "."
      OPENTLV_TEST_STRINGIFY(OPENTLV_VERSION_MINOR) "."
      OPENTLV_TEST_STRINGIFY(OPENTLV_VERSION_PATCH);
  const std::string prerelease = OPENTLV_VERSION_PRERELEASE;
  const std::string expected =
      prerelease.empty() ? core_version : core_version + "-" + prerelease;

  EXPECT_EQ(expected, OPENTLV_VERSION_STRING);
  EXPECT_FALSE(std::string(OPENTLV_GIT_COMMIT_HASH).empty());
  EXPECT_FALSE(std::string(OPENTLV_GIT_BRANCH).empty());
  EXPECT_EQ(core_version + "-" +
                OPENTLV_TEST_STRINGIFY(OPENTLV_VERSION_REVISION) + "-" +
                OPENTLV_GIT_COMMIT_HASH,
            OPENTLV_GIT_REPO_VERSION);
}

TEST(Unit_TLVVersion, runtime_api_reports_loaded_library_version) {
  EXPECT_EQ(OPENTLV_VERSION_MAJOR, tlv_version_major());
  EXPECT_EQ(OPENTLV_VERSION_MINOR, tlv_version_minor());
  EXPECT_EQ(OPENTLV_VERSION_PATCH, tlv_version_patch());
  EXPECT_EQ(OPENTLV_VERSION_REVISION, tlv_version_revision());
  EXPECT_STREQ(OPENTLV_VERSION_PRERELEASE, tlv_version_prerelease());
  EXPECT_STREQ(OPENTLV_VERSION_STRING, tlv_version_string());
  EXPECT_STREQ(OPENTLV_GIT_COMMIT_HASH, tlv_version_git_commit_hash());
  EXPECT_STREQ(OPENTLV_GIT_BRANCH, tlv_version_git_branch());
  EXPECT_STREQ(OPENTLV_GIT_TAG, tlv_version_git_tag());
  EXPECT_STREQ(OPENTLV_GIT_REPO_VERSION, tlv_version_git_repo());
}
