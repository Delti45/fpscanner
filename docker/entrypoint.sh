#!/bin/sh
# Wczytuje zmienne FP_* z pliku (domyślnie /data/server.env, zapisanego przez fp-provision-dev)
# i uruchamia polecenie kontenera. Plik NIE jest wykonywany jako skrypt: czytamy go linia
# po linii i eksportujemy wyłącznie klucze zaczynające się od FP_. Zmienne już ustawione w
# środowisku kontenera (np. w usłudze api z docker-compose.yml) mają pierwszeństwo przed plikiem.
set -eu
env_file="${FP_ENV_FILE:-/data/server.env}"
if [ -f "$env_file" ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            FP_*) [ -n "$(printenv "$key" || true)" ] || export "$key=$value" ;;
        esac
    done < "$env_file"
fi
exec "$@"
