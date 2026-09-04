# OpenTLV Git tags use Semantic Versioning without a prefix, for example
# 1.0.0 or 1.0.0-rc.1.
set(_OPENTLV_VERSION_MODULE_DIR "${CMAKE_CURRENT_LIST_DIR}")

# Remove the legacy manually configured value; pre-release now comes from Git.
unset(OPENTLV_VERSION_PRERELEASE CACHE)

execute_process(
    COMMAND git describe --tags --abbrev=0 --match "[0-9]*" HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RESULT_VARIABLE _opentlv_git_tag_result
    OUTPUT_VARIABLE _opentlv_described_tag
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

if(_opentlv_git_tag_result EQUAL 0)
    execute_process(
        COMMAND git rev-list -n 1 "${_opentlv_described_tag}"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE _opentlv_tag_commit_result
        OUTPUT_VARIABLE _opentlv_tag_commit
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT _opentlv_tag_commit_result EQUAL 0)
        message(FATAL_ERROR
            "Could not resolve Git tag '${_opentlv_described_tag}'")
    endif()

    execute_process(
        COMMAND git tag --points-at "${_opentlv_tag_commit}"
            --list "[0-9]*" --sort=-version:refname
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE _opentlv_tags_at_commit_result
        OUTPUT_VARIABLE _opentlv_tags_at_commit
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT _opentlv_tags_at_commit_result EQUAL 0)
        message(FATAL_ERROR
            "Could not inspect Git tags at commit '${_opentlv_tag_commit}'")
    endif()

    string(REPLACE "\r\n" "\n" _opentlv_tags_at_commit
        "${_opentlv_tags_at_commit}")
    string(REPLACE "\n" ";" _opentlv_tags_at_commit
        "${_opentlv_tags_at_commit}")

    set(OPENTLV_GIT_TAG "")
    set(_opentlv_prerelease_tag "")
    foreach(_tag IN LISTS _opentlv_tags_at_commit)
        if(_tag MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
            set(OPENTLV_GIT_TAG "${_tag}")
            break()
        elseif(NOT _opentlv_prerelease_tag AND _tag MATCHES
                "^[0-9]+\\.[0-9]+\\.[0-9]+-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*$")
            set(_opentlv_prerelease_tag "${_tag}")
        endif()
    endforeach()
    if(NOT OPENTLV_GIT_TAG)
        set(OPENTLV_GIT_TAG "${_opentlv_prerelease_tag}")
    endif()

    if(NOT OPENTLV_GIT_TAG MATCHES
            "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-([0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*))?$")
        message(FATAL_ERROR
            "Git tag '${OPENTLV_GIT_TAG}' is not a valid Semantic Version")
    endif()

    set(OPENTLV_VERSION_MAJOR "${CMAKE_MATCH_1}")
    set(OPENTLV_VERSION_MINOR "${CMAKE_MATCH_2}")
    set(OPENTLV_VERSION_PATCH "${CMAKE_MATCH_3}")
    set(OPENTLV_VERSION_PRERELEASE "${CMAKE_MATCH_5}")
    set(OPENTLV_VERSION
        "${OPENTLV_VERSION_MAJOR}.${OPENTLV_VERSION_MINOR}.${OPENTLV_VERSION_PATCH}")

    foreach(_component IN ITEMS
            OPENTLV_VERSION_MAJOR OPENTLV_VERSION_MINOR OPENTLV_VERSION_PATCH)
        if(${_component} MATCHES "^0[0-9]+$")
            message(FATAL_ERROR
                "Git tag '${OPENTLV_GIT_TAG}' contains a numeric component with leading zeroes")
        endif()
    endforeach()

    if(OPENTLV_VERSION_PRERELEASE)
        string(REPLACE "." ";" _opentlv_prerelease_identifiers
            "${OPENTLV_VERSION_PRERELEASE}")
        foreach(_identifier IN LISTS _opentlv_prerelease_identifiers)
            if(_identifier MATCHES "^0[0-9]+$")
                message(FATAL_ERROR
                    "Git tag '${OPENTLV_GIT_TAG}' contains a numeric pre-release identifier with leading zeroes")
            endif()
        endforeach()
    endif()

    execute_process(
        COMMAND git rev-list --count "${OPENTLV_GIT_TAG}..HEAD"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE _opentlv_git_revision_result
        OUTPUT_VARIABLE OPENTLV_VERSION_REVISION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT _opentlv_git_revision_result EQUAL 0)
        message(FATAL_ERROR
            "Could not count commits since Git tag '${OPENTLV_GIT_TAG}'")
    endif()
else()
    set(OPENTLV_GIT_TAG "unknown")
    set(OPENTLV_VERSION_MAJOR 0)
    set(OPENTLV_VERSION_MINOR 0)
    set(OPENTLV_VERSION_PATCH 0)
    set(OPENTLV_VERSION_PRERELEASE "")
    set(OPENTLV_VERSION "0.0.0")
    set(OPENTLV_VERSION_REVISION 0)
    message(WARNING
        "No Semantic Version Git tag found; using fallback version 0.0.0")
endif()

if(OPENTLV_VERSION_PRERELEASE)
    set(OPENTLV_VERSION_STRING
        "${OPENTLV_VERSION}-${OPENTLV_VERSION_PRERELEASE}")
else()
    set(OPENTLV_VERSION_STRING "${OPENTLV_VERSION}")
endif()

execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RESULT_VARIABLE _opentlv_git_hash_result
    OUTPUT_VARIABLE OPENTLV_GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT _opentlv_git_hash_result EQUAL 0)
    set(OPENTLV_GIT_COMMIT_HASH "unknown")
endif()

execute_process(
    COMMAND git rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RESULT_VARIABLE _opentlv_git_branch_result
    OUTPUT_VARIABLE OPENTLV_GIT_BRANCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT _opentlv_git_branch_result EQUAL 0)
    set(OPENTLV_GIT_BRANCH "unknown")
endif()

set(OPENTLV_GIT_REPO_VERSION
    "${OPENTLV_VERSION_STRING}-${OPENTLV_VERSION_REVISION}-${OPENTLV_GIT_COMMIT_HASH}")

function(opentlv_generate_version_files)
    configure_file(
        "${_OPENTLV_VERSION_MODULE_DIR}/../tlv/resources/version.h.in"
        "${PROJECT_BINARY_DIR}/generated/include/tlv/version.h"
        @ONLY
    )
    configure_file(
        "${_OPENTLV_VERSION_MODULE_DIR}/../tlv/resources/version.c.in"
        "${PROJECT_BINARY_DIR}/generated/src/version.c"
        @ONLY
    )

    message(STATUS
        "OpenTLV version: ${OPENTLV_VERSION_STRING} "
        "(${OPENTLV_GIT_REPO_VERSION}, branch ${OPENTLV_GIT_BRANCH})")
endfunction()
