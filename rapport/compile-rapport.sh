#!/bin/bash

# Compile le rapport en pdf avec luaLaTeX en mode non interactif
mkdir -p build
xelatex -f --shell-escape -interaction=nonstopmode -output-directory=build Rapport-BRELOT-Julien.tex

# Déplace le rapport dans le dossier rendu
mv build/Rapport-BRELOT-Julien.pdf Rapport-BRELOT-Julien.pdf