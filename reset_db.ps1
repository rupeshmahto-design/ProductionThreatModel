# Reset PostgreSQL password and create database
$psqlPath = "C:\Program Files\PostgreSQL\18\bin\psql.exe"

# Run psql with trust auth (no password prompt since we modified pg_hba.conf)
& $psqlPath -U postgres -h 127.0.0.1 -p 5432 -w -c "ALTER USER postgres PASSWORD 'postgres'; CREATE DATABASE threat_modeling;"

Write-Host "Password reset and database created successfully!"
