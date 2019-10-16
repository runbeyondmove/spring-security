-- 记住我功能用的表
CREATE TABLE persistent_logins (username VARCHAR(64) NOT NULL,
								series VARCHAR(64) PRIMARY KEY,
								token VARCHAR(64) NOT NULL,
								last_used TIMESTAMP NOT NULL);
-- 社交登录用的表
CREATE TABLE imooc_UserConnection (
	userId VARCHAR(255) NOT NULL,
	providerId VARCHAR(255) NOT NULL,
	providerUserId VARCHAR(255),
	rank INT NOT NULL,
	displayName VARCHAR(255),
	profileUrl VARCHAR(512),
	imageUrl VARCHAR(512),
	accessToken VARCHAR(512) NOT NULL,
	secret VARCHAR(512),
	refreshToken VARCHAR(512),
	expireTime BIGINT,
	PRIMARY KEY (userId, providerId, providerUserId))
ENGINE=INNODB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
CREATE UNIQUE INDEX UserConnectionRank ON imooc_UserConnection(userId, providerId, rank);