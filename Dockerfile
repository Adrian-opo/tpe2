# Usando a imagem base do Alpine Linux
FROM alpine:latest

# Instalando o netcat para ouvir nas portas e bash
RUN apk add --no-cache netcat-openbsd bash

# Copiando o script de inicialização para o contêiner
COPY start_services.sh /start_services.sh
RUN chmod +x /start_services.sh

# Expondo as portas desejadas (especificando TCP e UDP)
EXPOSE 53/udp 161/udp 67/udp 68/udp
# Removendo a porta 22 que está em uso e expondo as demais
EXPOSE 20/tcp 21/tcp 23/tcp 25/tcp 53/tcp 80/tcp 110/tcp 143/tcp 389/tcp 445/tcp 1433/tcp 3306/tcp 3389/tcp 5432/tcp 8080/tcp

# Comando padrão ao iniciar o contêiner
CMD ["/start_services.sh"]