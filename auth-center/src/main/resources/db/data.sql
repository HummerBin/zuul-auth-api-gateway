INSERT INTO `sys_role` VALUES (1,'ROLE_ADMIN'),(2,'ROLE_USER');
INSERT INTO `sys_user` VALUES (1,NULL,NULL,NULL,'admin',NULL,'admin'),(2,NULL,NULL,NULL,'zb',NULL,'zb');
INSERT INTO `sys_user_roles` VALUES (1,1),(2,2),(1,2);