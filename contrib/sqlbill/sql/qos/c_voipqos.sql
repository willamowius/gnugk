
-- QoS Measurements Table
-- used in conjunction with SQLAccounting Module

-- Copyright (c) 2007, Simon Horne
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

CREATE TABLE voipqos (
  id BIGSERIAL, 
  confid TEXT DEFAULT ''::text NOT NULL, 
  callid INTEGER, 
  session INTEGER NOT NULL, 
  sendip INET DEFAULT '127.0.0.1'::INET NOT NULL, 
  sentport NUMERIC(5,0), 
  recvip INET DEFAULT '127.0.0.1'::INET NOT NULL, 
  recvport NUMERIC(5,0), 
  isnat INTEGER, 
  avgdelay NUMERIC(5,0), 
  packetloss NUMERIC(5,0), 
  packetpercent NUMERIC(5,2), 
  avgjitter NUMERIC(5,0), 
  bandwidth NUMERIC(8,0), 
  timestamp TIMESTAMP(0) WITH TIME ZONE, 
  CONSTRAINT "voipqos_pkey" PRIMARY KEY("id")
) WITH OIDS;


CREATE OR REPLACE FUNCTION voipqos_callid() RETURNS trigger AS
$body$
BEGIN
  SELECT INTO NEW.callid a.id FROM voipcall a WHERE a.h323confid = NEW.confid;
  RETURN NEW;
END;
$body$
LANGUAGE 'plpgsql' IMMUTABLE;


CREATE TRIGGER voipqos_call_tr BEFORE INSERT 
ON voipqos FOR EACH ROW 
EXECUTE PROCEDURE voipqos_callid();

