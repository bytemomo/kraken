
default:
    @just --list

build_pdf_documentation folder_name:
    #!/bin/bash
    if [[ ! -d "{{folder_name}}" ]]; then
        echo "Folder '{{folder_name}}' does not exist."
        exit 1
    fi

    pushd {{folder_name}}
    pandoc --pdf-engine=typst --output={{folder_name}}_doc.pdf documentation.md -V  mainfont="Arial"
    pandoc --pdf-engine=typst --output={{folder_name}}_req.pdf requirements.md -V  mainfont="Arial"
    popd
