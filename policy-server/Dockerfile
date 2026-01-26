# Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY ../agent/Nxmx.Agent.csproj ../agent/
COPY Nxmx.PolicyServer.csproj ./
RUN dotnet restore ./Nxmx.PolicyServer.csproj

COPY .. .
RUN dotnet publish ./policy-server/Nxmx.PolicyServer.csproj -c Release -o /app/publish

# Run
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/publish .

# Render sets $PORT. Bind to it.
ENV ASPNETCORE_URLS=http://0.0.0.0:${PORT}
EXPOSE 10000

ENTRYPOINT ["dotnet", "Nxmx.PolicyServer.dll"]
