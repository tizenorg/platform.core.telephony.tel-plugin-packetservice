INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (1, 'Samsung 3G', '45001');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (2, 'Vodafone.de', '26202');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (3, 'Vodafone.uk', '23415');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (4, 'O2 UK', '23410');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (5, 'Movistar', '21407');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (6, 'Orange ES', '21403');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (7, 'Orange UK', '23433');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (8, 'Orange FR', '20801');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (9, 'ATnT', '31041');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (10, 'Airtel India', '40445');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (11, 'Vodafone India', '40486');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (12, 'China Unicom', '46001');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (13, 'BSNL', '40471');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (14, 'Vodafone India Delhi', '40411');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (15, 'Airtel India Delhi', '40410');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (16, 'E Plus', '26203');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (17, 'Vodafone ES', '21401');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (18, 'Orange DE', '26207');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (19, 'SKT', '45005');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (20, 'F SFR', '20810');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (21, 'T Mobile DE', '26201');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (22, 'NTT Docomo JP', '44010');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (23, 'KT', '45008');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (24, 'play', '26006');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (25, 'Plus GSM', '26001');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (26, 'T Mobile US', '31026');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (27, 'Tizen', '11111');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (28, 'T Mobile UK', '23430');
INSERT INTO "network_info" (network_info_id, network_name, mccmnc) VALUES (29, 'T Mobile PL', '26002');

INSERT INTO "max_pdp"(network_info_id, max_pdp_3g) VALUES(1, 2);
INSERT INTO "max_pdp"(network_info_id, max_pdp_3g) VALUES(2, 3);

INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(1, 'Samsung3G','nate.sktelecom.com',0,NULL,NULL,1,'168.219.61.250:8080','http://www.samsung.com',300, 0,0,NULL,0,NULL,NULL,1,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(2, 'Samsung3G MMS','nate.sktelecom.com',0,NULL,NULL,1,'165.213.73.234:7082','http://165.213.73.234:7082/01030016056=01030016056',300, 0,0,NULL,0,NULL,NULL,1,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(3, 'Voda DE Web','web.vodafone.de',0,NULL,NULL,1,NULL,'http://www.vodafone.de',300, 0,0,NULL,0,NULL,NULL,2,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(4, 'Voda DE MMS','event.vodafone.de',0,NULL,NULL,1,'139.7.29.17:80','http://139.7.24.1/servlets/mms',300, 0,0,NULL,0,NULL,NULL,2,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(5, 'Voda DE Wap','wap.vodafone.de',0,NULL,NULL,1,'139.7.29.1:80','http://live.vodafone.com',300, 0,0,NULL,0,NULL,NULL,2,5, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(6, 'Voda UK 3G','internet',0,'wap','wap',1,NULL,NULL,300, 0,0,NULL,0,NULL,NULL,3,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(7, 'Voda UK MMS','wap.vodafone.co.uk',0,'wap','wap',1,'212.183.137.12:8799','http://mms.vodafone.co.uk/servlets/mms',300, 0,0,NULL,0,NULL,NULL,3,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(9, 'O2 UK Web','mobile.o2.co.uk',0,'o2web','password',1,NULL,'',120,0,0,NULL,0,NULL,NULL,4,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(10, 'O2 UK MMS','wap.o2.co.uk',0,'o2wap','password',1,'193.113.200.195:8080','http://mmsc.mms.o2.co.uk:8002',120,0,0,NULL,0,NULL,NULL,4,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(11, 'Movistar 3G','movistar.es',1,'movistar','movistar',1,NULL,'http://wap.movistar.com',300, 0,0,NULL,0,NULL,NULL,5,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(12, 'Movista MMS','mms.movistar.es',1,'MOVISTAR@mms','MOVISTAR',1,'10.138.255.5:8080','http://mms.movistar.com',300, 0,0,NULL,0,NULL,NULL,5,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(13, 'Orange Internet','internet',1,'orange','orange',1,NULL,'http://www.orange.es',300, 0,0,NULL,0,NULL,NULL,6,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(14, 'Orange MMS','orangemms',1,'orange','orange',1,'172.22.188.25:8080','http://mms.orange.es',300, 0,0,NULL,0,NULL,NULL,6,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(15, 'Orange World','orangeworld',1,'orange','orange',1,'10.132.61.10:8080','http://wap.orange.es',300, 0,0,NULL,0,NULL,NULL,6,5, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(16, 'Orange Internet','orangeinternet',1,NULL,NULL,1,NULL,'http://orangeworld.co.uk/',300, 0,0,NULL,0,NULL,NULL,7,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(17, 'Orange MMS','orangemms',1,NULL,NULL,1,'192.168.224.10:8080','http://mms.orange.co.uk/',300, 0,0,NULL,0,NULL,NULL,7,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(18, 'Orange world','orange',1,'orange','orange',1,NULL,'http://www.orange.fr/',0,0,0,NULL,0,NULL,NULL,8,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(19, 'Orange MMS','orange.acte',1,'orange','orange',1,'192.168.10.200:8080','http://mms.orange.fr/',300, 0,0,NULL,0,NULL,NULL,8,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(20, 'ATnT ISP','wap.cingular',0,NULL,NULL,1,'wireless.cingular.com:80',NULL,0,0,0,NULL,0,NULL,NULL,9,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(21, 'ATnT MMS','wap.cingular',0,NULL,NULL,1,'wireless.cingular.com:80','http://mmsc.cingular.com/',0,0,0,NULL,0,NULL,NULL,9,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(22, 'Airtel India','airtelgprs.com',0,NULL,NULL,1,NULL,'http://airtel.in',0,0,0,NULL,0,NULL,NULL,10,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(23, 'Airtel MMS','airtelmms.com',0,NULL,NULL,1,'100.1.201.172:8799','http://100.1.201.171:10021/mmsc',0,0,0,NULL,0,NULL,NULL,10,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(24, 'Vodafone India 3G','www',0,NULL,NULL,1,NULL,'http://www.vodafone.in',0,0,0,NULL,0,NULL,NULL,11,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(25, 'Vodadone India MMS','portalnmms',0,NULL,NULL,1,'10.10.1.100:9401','http://mms1.live.vodafone.in/mms/',0,0,0,NULL,0,NULL,NULL,11,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(26, 'China Unicom 3G','uninet',0,NULL,NULL,1,NULL,'http://www.wo.com.cn',0,0,0,NULL,0,NULL,NULL,12,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(27, 'China Unicom MMS','3gwap',0,NULL,NULL,1,'10.0.0.172:80','http://mmsc.myuni.com.cn',0,0,0,NULL,0,NULL,NULL,12,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(28, 'BSNL 3G India','gprssouth.cellone.in',0,'ppp','ppp123',1,NULL,'http://www.bsnl.co.in',300,0,0,NULL,0,NULL,NULL,13,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(29, 'BSNL India MMS','bsnlmms',0,NULL,NULL,1,'10.210.10.11:8080','http://bsnlmmsc.in:8514',0,0,0,NULL,0,NULL,NULL,13,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(30, 'Vodafone 3G India Delhi','portalnmms',0,NULL,NULL,1,'10.10.1.100:9401','http://www.vodafone.in',0,0,0,NULL,0,NULL,NULL,14,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(31, 'Vodafone India Delhi MMS','portalnmms',0,NULL,NULL,1,'10.10.1.100:9401','http://mms1.live.vodafone.in/mms/',0,0,0,NULL,0,NULL,NULL,14,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(32, 'Airtel 3G India Delhi','airtelgprs.com',0,NULL,NULL,1,'100.1.200.99:8080','http://airtel.in',0,0,0,NULL,0,NULL,NULL,15,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(33, 'Airtel India Delhi MMS','airtelmms.com',0,NULL,NULL,1,'100.1.201.172:8799','http://100.1.201.171:10021/mmsc',0,0,0,NULL,0,NULL,NULL,15,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(34, 'E Plus 3G','internet.eplus.de',1,'eplus','internet',1,NULL,NULL,60,0,0,NULL,0,'212.23.97.2','212.23.97.3',16,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(35, 'E Plus MMS','mms.eplus.de',1,'mms','eplus',1,'212.23.97.153:5080','http://mms/eplus',60,0,0,NULL,0,NULL,NULL,16,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(36, 'Voda ES Web','airtelnet.es',0,'vodafone','vodafone',1,NULL,'http://www.vodafone.es',300,0,0,NULL,0,NULL,NULL,17,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(37, 'Voda ES MMS','mms.vodafone.net',0,'wap@wap','wap125',1,'212.73.32.10:80','http://www.vodafone.es',300, 0,0,NULL,0,NULL,NULL,17,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(38, 'O2 Internet','internet',0,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,18,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(39, 'O2 MMS','internet',0,NULL,NULL,1,'82.113.100.5:8080','http://10.81.0.7:8002',300,0,0,NULL,0,NULL,NULL,18,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(40, 'SKT Internet','web.sktelecom.com',0,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,19,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(41, 'SKT MMS','web.sktelecom.com',0,NULL,NULL,0,'220.103.230.150:9093','http://omms.nate.com:9082/oma_mms',300, 0,0,NULL,0,NULL,NULL,19,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(42, 'SFR Internet','sl2sfr',1,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,20,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(43, 'SFR MMS','mmssfr',1,NULL,NULL,1,'10.151.0.1:8080','http://mms1',300,0,0,NULL,0,NULL,NULL,20,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(44, 'T Mobile Internet','internet.t-mobile',1,'t-mobile','tm',1,NULL,NULL,150,0,0,NULL,0,NULL,NULL,21,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(45, 'T Mobile MMS','internet.t-mobile',1,'t-mobile','tm',1,'172.28.23.131:8008','http://mms.t-mobile.de/servlets/mms',150,0,0,NULL,0,NULL,NULL,21,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(46, 'NTT Docomo JP','spmode.ne.jp',0,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,22,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(47, 'NTT Docomo JP','mopera.net',0,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,22,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(48, 'KT Internet','default.ktfwing.com',0,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,23,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(49, 'KT MMS','default.ktfwing.com',0,NULL,NULL,1,NULL,'http://mmsc.ktfwing.com:9082',300,0,0,NULL,0,NULL,NULL,23,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(50, 'Play Internet','internet',0,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,24,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(51, 'Play MMS','mms',0,NULL,NULL,1,'10.10.25.5:8080','http://10.10.28.164/mms/wapenc',300,0,0,NULL,0,NULL,NULL,24,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(52, 'Plus GSM Internet','www.plusgsm.pl',0,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,25,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(53, 'Plus GSM MMS','mms.plusgsm.pl',0,NULL,NULL,1,'212.2.96.16:8080','http://mms.plusgsm.pl:8002',300,0,0,NULL,0,NULL,NULL,25,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(54, 'T Mobile Internet','epc.tmobile.com',0,NULL,NULL,1,NULL,NULL,300,0,0,NULL,0,NULL,NULL,26,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(55, 'T Mobile MMS','epc.tmobile.com',0,NULL,NULL,1,NULL,'http://mms.msg.english.t-mobile.com/mms/wapenc',300,0,0,NULL,0,NULL,NULL,26,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(56, 'Tizen Internet','emul.tizen.com',0,NULL,NULL,1,NULL,'http://www.samsung.com',300, 0,0,NULL,0,NULL,NULL,27,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(57, 'Tizen3G MMS','emul.tizen.com',0,NULL,NULL,1,NULL,'http://tizen.mms.server.com',300, 0,0,NULL,0,NULL,NULL,27,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(58, 'T Mobile Internet','general.t-mobile.uk',1,'user','tm',1,NULL,'http://www.t-mobile-favourites.co.uk',300, 0,0,NULL,0,NULL,NULL,28,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(59, 'T Mobile MMS','general.t-mobile.uk',1,'user','tm',1,'149.254.201.135:8080','http://mmsc.t-mobile.co.uk:8002',300, 0,0,NULL,0,NULL,NULL,28,2, 0, 1, 0);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(60, 'T Mobile Internet','internet',0,NULL,NULL,1,NULL,NULL,300, 0,0,NULL,0,NULL,NULL,29,1,0,1,1);
INSERT INTO "pdp_profile" (profile_id, profile_name, apn, auth_type, auth_id, auth_pwd, pdp_protocol,proxy_ip_addr,home_url,linger_time, traffic_class,is_static_ip_addr,ip_addr,is_static_dns_addr,dns_addr1,dns_addr2,network_info_id,svc_category_id, hidden, editable, default_internet_con)	VALUES(61, 'T Mobile MMS','mms',0,NULL,NULL,1,'213.158.194.226:8080','http://mms/servlets/mms',300, 0,0,NULL,0,NULL,NULL,29,2, 0, 1, 0);

