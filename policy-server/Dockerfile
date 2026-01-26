	   
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# copy csproj first for faster restore
COPY policy-server/Nxmx.PolicyServer.csproj policy-server/
COPY Agent/Nxmx.Agent.csproj Agent/
RUN dotnet restore policy-server/Nxmx.PolicyServer.csproj

# copy everything and publish
COPY . .
RUN dotnet publish policy-server/Nxmx.PolicyServer.csproj -c Release -o /app/publish

	 
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/publish .

# Render injects PORT
ENV ASPNETCORE_URLS=http://0.0.0.0:${PORT}
ENTRYPOINT ["dotnet","Nxmx.PolicyServer.dll"]