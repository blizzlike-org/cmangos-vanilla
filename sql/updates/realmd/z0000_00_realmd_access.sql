DROP TABLE IF EXISTS `realm_access`;
CREATE TABLE `realm_access` (
  `realmid` int(11) unsigned NOT NULL DEFAULT '0',
  `acctid` bigint(20) unsigned NOT NULL,
  `gmlevel` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`acctid`,`realmid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC COMMENT='Access per realm';

ALTER TABLE account DROP COLUMN gmlevel;
