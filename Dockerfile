FROM openjdk:17-jdk-alpine

WORKDIR /app

ARG JAR_FILE=*.jar

COPY target/${JAR_FILE} /app/app.jar

EXPOSE 8080

CMD ["java", "-jar", "/app/app.jar"]