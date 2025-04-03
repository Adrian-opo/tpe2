#!/bin/bash

echo "Iniciando serviços simulados..."

# Lista de portas TCP para simular serviços (removendo a porta 22 que está em uso)
TCP_PORTS="20 21 23 25 53 80 110 143 389 445 1433 3306 3389 5432 8080"

# Lista de portas UDP para simular serviços
UDP_PORTS="53 67 68 161"

# Iniciando serviços TCP
for port in $TCP_PORTS; do
  echo "Abrindo porta TCP $port"
  nc -l -p $port -k & 
done

# Iniciando serviços UDP
for port in $UDP_PORTS; do
  echo "Abrindo porta UDP $port"
  nc -l -u -p $port -k &
done

echo "Todos os serviços foram iniciados!"

# Mantém o contêiner em execução
tail -f /dev/null
