/*******************************************************************
Source: https://github.com/martinisaksen/SimpleSQLScripts
Author: Martin Isaksen
License: MIT License
*******************************************************************/

/*******************************************************************

This script will output the permissions for a Login or SQL User.
The permissions are for Server, Database, and Object level.

The table outputs are as following:
1. List of roles the login is a member of
2. List of database users the login is tied to
3. List of all peremissions the login has
4. List of actual permissions the login has. DENY overrides GRANT.

*******************************************************************/

-- CHANGE TO THE ACCOUNT YOU WANT TO CHECK PERMISSIONS FOR
DECLARE @Account sysname = N'sa';

----------------------------------------------------------------
----------------------------------------------------------------
-- Declare variables
DECLARE
    @LoginSID VARBINARY(85)
    ,@NewLine CHAR(2) = CONCAT(CHAR(10), CHAR(13))
    ,@Login sysname;

-- Get actual login used
DROP TABLE IF EXISTS #Path;

CREATE TABLE #Path
(
    account_name sysname
    ,type VARCHAR(8)
    ,privilege VARCHAR(8)
    ,mapped_login_name sysname
    ,permission_path VARCHAR(128)
);

BEGIN TRY
    INSERT INTO #Path
    (
        account_name
        ,type
        ,privilege
        ,mapped_login_name
        ,permission_path
    )
    EXEC sys.xp_logininfo @acctname = @Account, @option = 'all';
END TRY
BEGIN CATCH
    INSERT INTO #Path
    (
        account_name
        ,type
        ,privilege
        ,mapped_login_name
    )
    SELECT
        @Account
        ,'SQL User'
        ,CASE
             WHEN SRM.role_principal_id = 3 THEN 'admin'
             ELSE 'user'
         END
        ,@Account
    FROM
        sys.server_principals AS SP
        LEFT OUTER JOIN sys.server_role_members AS SRM ON SP.principal_id = SRM.member_principal_id
    WHERE
        SP.name = @Account;
END CATCH;

-- Check if login is a server admin
IF EXISTS
    (
        SELECT
            *
        FROM
            #Path AS P
        WHERE
            P.privilege = 'admin'
    )
BEGIN
    SELECT
        CONCAT(@Account, ' is a SERVER ADMIN on this server') AS [*** SERVER ADMIN ***];

    SELECT
        *
    FROM
        #Path AS P;
END;
ELSE
BEGIN;

    -- Get actual login account
    -- TODO: permission_path can return multiple accounts. Need to handle this when that happens
    SELECT
        @Login = ISNULL(P.permission_path, P.mapped_login_name)
    FROM
        #Path AS P;

    -- Get the SID for the login. This is used in other queries.
    SELECT
        @LoginSID = SP.sid
    FROM
        sys.server_principals AS SP
    WHERE
        SP.name = @Login;

    -- Set up tables to store output
    DROP TABLE IF EXISTS #Roles;
    DROP TABLE IF EXISTS #Users;
    DROP TABLE IF EXISTS #Permissions;

    CREATE TABLE #Roles
    (
        DatabaseName sysname
        ,RoleName sysname
        ,DatabaseId INT
        ,PrincipalId INT
    );

    CREATE TABLE #Users
    (
        DatabaseName sysname
        ,UserName sysname
    );

    CREATE TABLE #Permissions
    (
        DatabaseName sysname
        ,UserName sysname
        ,Class NVARCHAR(60)
        ,Permission NVARCHAR(128)
        ,Status NVARCHAR(60)
        ,Object NVARCHAR(128)
        ,ObjectType NVARCHAR(60)
    );

    -- Get server roles for login
    INSERT INTO #Roles
    (
        DatabaseName
        ,RoleName
    )
    SELECT
        'SERVER'
        ,SP2.name
    FROM
        sys.server_principals AS SP
        INNER JOIN sys.server_role_members AS SRM ON SP.principal_id = SRM.member_principal_id
        INNER JOIN sys.server_principals AS SP2 ON SRM.role_principal_id = SP2.principal_id
    WHERE
        SP.sid = @LoginSID;

    -- Get server level permissions for login
    INSERT INTO #Permissions
    (
        DatabaseName
        ,UserName
        ,Class
        ,Permission
        ,Status
        ,Object
        ,ObjectType
    )
    SELECT
        'SERVER'
        ,SP2.name
        ,SP.class_desc
        ,SP.permission_name
        ,SP.state_desc
        ,CONCAT(S.name + '.', O.name)
        ,O.type_desc
    FROM
        sys.server_permissions AS SP
        INNER JOIN sys.server_principals AS SP2 ON SP.grantee_principal_id = SP2.principal_id
        LEFT OUTER JOIN sys.objects AS O ON O.object_id = SP.major_id
        LEFT OUTER JOIN sys.schemas AS S ON S.schema_id = O.schema_id
    WHERE
        SP2.sid = @LoginSID;

    -- Get server level permissions for server roles
    INSERT INTO #Permissions
    (
        DatabaseName
        ,UserName
        ,Class
        ,Permission
        ,Status
        ,Object
        ,ObjectType
    )
    SELECT
        'SERVER'
        ,DP2.name
        ,DP.class_desc
        ,DP.permission_name
        ,DP.state_desc
        ,CONCAT(S.name + '.', O.name)
        ,O.type_desc
    FROM
        sys.database_permissions AS DP
        INNER JOIN sys.database_principals AS DP2 ON DP.grantee_principal_id = DP2.principal_id
        LEFT OUTER JOIN sys.objects AS O ON O.object_id = DP.major_id
        LEFT OUTER JOIN sys.schemas AS S ON S.schema_id = O.schema_id
        INNER JOIN #Roles AS R ON R.PrincipalId = DP2.principal_id;

    -- For each database
    DECLARE c_Databases CURSOR FAST_FORWARD FOR 
    SELECT
        QUOTENAME(D.name)
    FROM
        sys.databases AS D
    WHERE
        HAS_DBACCESS(D.name) = 1;

    DECLARE @DatabaseName sysname;

    OPEN c_Databases;

    FETCH NEXT FROM c_Databases
    INTO
        @DatabaseName;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        DECLARE @SQL NVARCHAR(MAX) = 'USE ?;' + @NewLine;

        -- Get database level permissions for login
        SET @SQL += N'
        INSERT INTO #Users
        (
            DatabaseName
            ,UserName
        )
        SELECT
            @DatabaseName
            ,DP.name
        FROM
            sys.database_principals AS DP
        WHERE
            DP.sid = @LoginSID;' + @NewLine;

        -- Get database roles for login
        SET @SQL += N'
        INSERT INTO #Roles
        (
            DatabaseName
            ,RoleName
            ,DatabaseId
            ,PrincipalId
        )
        SELECT
            @DatabaseName
            ,DP2.name
            ,DB_ID()
            ,DP2.principal_id
        FROM
            sys.database_principals AS DP
            INNER JOIN sys.database_role_members AS DRM ON DRM.member_principal_id = DP.principal_id
            INNER JOIN sys.database_principals AS DP2 ON DP2.principal_id = DRM.role_principal_id
        WHERE
            DP.sid = @LoginSID;' + @NewLine;

        -- Get database level permissions for user
        SET @SQL += N'
        INSERT INTO #Permissions
        (
            DatabaseName
            ,UserName
            ,Class
            ,Permission
            ,Status
            ,Object
            ,ObjectType
        )
        SELECT
            @DatabaseName
            ,DP2.name
            ,DP.class_desc
            ,DP.permission_name
            ,DP.state_desc
            ,CONCAT(s.name + ''.'',o.name)
            ,o.type_desc
        FROM
            sys.database_permissions AS DP
            INNER JOIN sys.database_principals AS DP2 ON DP.grantee_principal_id = DP2.principal_id
            LEFT OUTER JOIN sys.objects AS O ON o.object_id = DP.major_id
            LEFT OUTER JOIN sys.schemas AS S ON s.schema_id = o.schema_id
        WHERE
            DP2.sid = @LoginSID;' + @NewLine;

        -- Get database level permissions for roles
        SET @SQL += N'
        INSERT INTO #Permissions
        (
            DatabaseName
            ,UserName
            ,Class
            ,Permission
            ,Status
            ,Object
            ,ObjectType
        )
        SELECT
            @DatabaseName
            ,DP2.name
            ,DP.class_desc
            ,DP.permission_name
            ,DP.state_desc
            ,CONCAT(s.name + ''.'',o.name)
            ,o.type_desc
        FROM
            sys.database_permissions AS DP
            INNER JOIN sys.database_principals AS DP2 ON DP.grantee_principal_id = DP2.principal_id
            LEFT OUTER JOIN sys.objects AS O ON o.object_id = DP.major_id
            LEFT OUTER JOIN sys.schemas AS S ON s.schema_id = o.schema_id
            INNER JOIN #Roles AS R ON R.DatabaseId = DB_ID() AND R.PrincipalId = DP2.principal_id;' + @NewLine;

        -- Make sure the USE statement gets the next database so the code executes on the next database
        SET @SQL = REPLACE(@SQL, '?', @DatabaseName);

        EXEC sp_executesql @SQL, N'@DatabaseName sysname, @LoginSID VARBINARY(85)', @DatabaseName = @DatabaseName, @LoginSID = @LoginSID;

        FETCH NEXT FROM c_Databases
        INTO
            @DatabaseName;
    END;

    CLOSE c_Databases;
    DEALLOCATE c_Databases;

    -- Display permissions
    SELECT
        LP.DatabaseName
        ,LP.RoleName
    FROM
        #Roles AS LP;

    SELECT
        U.DatabaseName
        ,U.UserName
    FROM
        #Users AS U;

    -- Show all permissions
    SELECT
        P.DatabaseName
        ,P.UserName
        ,P.Class
        ,P.Permission
        ,P.Status
        ,P.Object
        ,P.ObjectType
    FROM
        #Permissions AS P;

    -- Show actual permissions
    -- TODO: Actual permissions if any are conflicting between higher and lower objects
    SELECT
        ISNULL(D.DatabaseName, G.DatabaseName) AS DatabaseName
        ,ISNULL(D.UserName, G.UserName) AS UserName
        ,ISNULL(D.Class, G.Class) AS Class
        ,ISNULL(D.Permission, G.Permission) AS Permission
        ,ISNULL(D.Status, G.Status) AS Status
        ,ISNULL(D.Object, G.Object) AS Object
        ,ISNULL(D.ObjectType, G.ObjectType) AS ObjectType
    FROM
        (
            SELECT
                P.DatabaseName
                ,P.UserName
                ,P.Class
                ,P.Permission
                ,P.Status
                ,P.Object
                ,P.ObjectType
            FROM
                #Permissions AS P
            WHERE
                P.Status = 'GRANT'
        ) AS G
        FULL OUTER JOIN
            (
                SELECT
                    P2.DatabaseName
                    ,P2.UserName
                    ,P2.Class
                    ,P2.Permission
                    ,P2.Status
                    ,P2.Object
                    ,P2.ObjectType
                FROM
                    #Permissions AS P2
                WHERE
                    P2.Status = 'DENY'
            ) AS D ON D.DatabaseName = G.DatabaseName
                       AND D.Object = G.Object
                       AND D.ObjectType = G.ObjectType;
END;