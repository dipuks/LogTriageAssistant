FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["LogTriageAssistant.csproj", "./"]
RUN dotnet restore "LogTriageAssistant.csproj"
COPY . .
RUN dotnet publish "LogTriageAssistant.csproj" -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .
RUN mkdir -p /app/App_Data && chown -R $APP_UID:$APP_UID /app
USER $APP_UID
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "LogTriageAssistant.dll"]
