# Architectural guardrails, deliberately limited to the canonical processing engines.
# Semantic behavior is covered by Integration_Tlv_Pipeline and component tests.
get_filename_component(root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

function(forbid path pattern reason)
    file(READ "${root}/${path}" source)
    # Ignore comments so explanations of the boundary do not trigger the guard.
    string(REGEX REPLACE "/\\*([^*]|\\*+[^*/])*\\*+/" "" source "${source}")
    string(REGEX REPLACE "//[^\n]*" "" source "${source}")
    if(source MATCHES "${pattern}")
        message(FATAL_ERROR "${path}: ${reason}")
    endif()
endfunction()

foreach(path reader/reader.c reader/tree.c reader/visitor.c writer/writer.c writer/tree.c)
    forbid("tlv/src/${path}" "(malloc|calloc|realloc|alloca)[ \t\r\n]*\\("
           "Reader/Writer storage must remain caller-owned")
    forbid("tlv/src/${path}" "#include[ \t]+[\"<]tlv/(document|query|schema|codec|builtins)/"
           "lower processing layers must not depend on higher layers or protocols")
endforeach()
foreach(path reader/tree.c reader/visitor.c query/query.c document/document.c writer/tree.c)
    forbid("tlv/src/${path}" "tlv_format_(decode|encode|measure)[ \t\r\n]*\\(|->[ \t]*(decode|encode|measure)[ \t\r\n]*\\("
           "wire processing must go through Reader/Writer")
    forbid("tlv/src/${path}" "tlv_(fields|variable|packed|fixed)_(decode|encode|measure)[ \t\r\n]*\\("
           "layout mechanics belong to Format, not higher processing layers")
endforeach()
foreach(path reader/reader.c reader/tree.c)
    forbid("tlv/src/${path}" "#include[ \t]+[\"<]tlv/(writer/|reader/visitor)"
           "Reader engines must not depend on encoding or Visitor adapters")
endforeach()
foreach(path writer/writer.c writer/tree.c)
    forbid("tlv/src/${path}" "#include[ \t]+[\"<]tlv/reader/"
           "Writer engines consume semantic content, not Reader traversal")
endforeach()
forbid("tlv/src/reader/reader.c" "#include[ \t]+[\"<]tlv/reader/tree"
       "Reader must not depend on Tree Reader")
forbid("tlv/src/writer/writer.c" "#include[ \t]+[\"<]tlv/writer/tree"
       "Writer must not depend on Tree Writer")
foreach(path query/query.c document/document.c reader/visitor.c)
    forbid("tlv/src/${path}" "tlv_(read|read_diag|read_source_diag)[ \t\r\n]*\\("
           "higher layers must consume cursor traversal instead of parsing bytes")
endforeach()
forbid("tlv/src/query/query.c" "tlv_(reader_next|reader_next_diag|reader_next_source_diag)[ \t\r\n]*\\("
       "nested Query traversal belongs to Tree Reader")
message(STATUS "Canonical pipeline dependency guardrails passed")
