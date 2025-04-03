#!/bin/sh

# Lista de portas TCP para ouvir
TCP_PORTS="20 21 22 23 25 53 80 110 143 389 445 1433 3306 3389 5432 8080"

# Lista de portas UDP para ouvir
UDP_PORTS="53 161 67 68"

# Inicia o netcat em cada porta TCP
for PORT in $TCP_PORTS; do
  nc -lk -p $PORT &
done

# Inicia o netcat em cada porta UDP
for PORT in $UDP_PORTS; do
  nc -ul -p $PORT &
done

# Mantém o contêiner em execução
wait