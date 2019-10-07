function(osqueryExamplesMain)
    add_executable(osquery_examples_exampleextension example_extension.cpp)

    target_link_libraries(osquery_examples_exampleextension PRIVATE
        osquery_cxx_settings
        osquery_sdk_pluginsdk
    )
endfunction()

osqueryExamplesMain()
