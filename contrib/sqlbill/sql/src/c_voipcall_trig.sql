-- Trigger procedures for voipcall pre- and postprocessing
--
-- VoIP Billing Platform for GnuGk
-- Copyright (c) 2004, Michal Zygmuntowicz
--
-- This work is published under the GNU Public License (GPL)
-- see file COPYING for details

-- Normalize strings (convert special FreeRADIUS characters)
-- and find the account associated with the call
CREATE OR REPLACE FUNCTION voipcall_preprocess_fields()
	RETURNS TRIGGER AS
'
DECLARE
	userid INT;
BEGIN
	NEW.h323id := radius_xlat(NEW.h323id);
	NEW.gkid := radius_xlat(NEW.gkid);
	NEW.callingstationid := radius_xlat(NEW.callingstationid);
	NEW.calledstationid := radius_xlat(NEW.calledstationid);

	userid := match_user(NEW.h323id, NEW.callingstationip);
	IF userid IS NOT NULL THEN
		IF NEW.accountid IS NULL THEN
			SELECT INTO NEW.accountid, NEW.currencysym, NEW.h323id 
					A.id, A.currencysym, U.h323id
				FROM voipaccount A JOIN voipuser U ON A.id = U.accountid 
				WHERE U.id = userid;
		END IF;
	END IF;

	RETURN NEW;
END;
' LANGUAGE 'plpgsql';

-- Find tariff information for the call
CREATE OR REPLACE FUNCTION voipcall_match_tariff()
	RETURNS TRIGGER AS
'
DECLARE
	userid INT;
BEGIN
	IF NEW.price IS NOT NULL AND NEW.cost IS NOT NULL THEN
		RETURN NEW;
	END IF;

	IF NEW.accountid IS NULL THEN
		userid := match_user(NEW.h323id, NEW.callingstationip);
		IF userid IS NOT NULL THEN
			SELECT INTO NEW.accountid, NEW.currencysym, NEW.h323id
					A.id, A.currencysym, U.h323id
				FROM voipuser U JOIN voipaccount A ON U.accountid = A.id
				WHERE U.id = userid;
		END IF;
	END IF;

	IF NEW.price IS NULL AND NEW.accountid IS NOT NULL THEN
		SELECT INTO NEW.price, NEW.tariffdesc, NEW.initialincrement,
				NEW.regularincrement T.price, D.description, T.initialincrement,
				T.regularincrement
			FROM match_tariff(NEW.calledstationid, NEW.accountid, NEW.currencysym) AS T
				JOIN voiptariffdst D ON T.dstid = D.id;
	END IF;
		
	RETURN NEW;
END;
' LANGUAGE 'plpgsql';

-- Calculate total call cost (duration*price) and substract
-- difference from the associated account balance
CREATE OR REPLACE FUNCTION voipcall_update_cost()
	RETURNS TRIGGER AS
'
DECLARE
	costdiff NUMERIC(12,4);
BEGIN
	IF NEW.price IS NOT NULL THEN
		IF NEW.duration = 0 THEN
			NEW.cost := 0;
		ELSE
			NEW.cost := NEW.price::NUMERIC(12,4) * NEW.initialincrement::NUMERIC(12,4)
				/ 60::NUMERIC(12,4);
		END IF;
		IF NEW.duration > NEW.initialincrement THEN
			NEW.cost := NEW.cost + NEW.price::NUMERIC(12,4) 
				* ((NEW.duration - NEW.initialincrement + NEW.regularincrement - 1)::INT 
					/ NEW.regularincrement::INT)::NUMERIC(12,4) 
				* NEW.regularincrement::NUMERIC(12,4) / 60::NUMERIC(12,4);
		END IF;
		IF NEW.accountid IS NOT NULL THEN
			IF TG_OP = ''UPDATE'' THEN
				IF OLD.cost IS NULL THEN
					costdiff := NEW.cost;
				ELSE
					costdiff := NEW.cost - OLD.cost;
				END IF;
			ELSE
				costdiff := NEW.cost;
			END IF;
			UPDATE voipaccount SET balance = balance - costdiff
				WHERE id = NEW.accountid;
		END IF;
	END IF;
	RETURN NEW;
END;
' LANGUAGE 'plpgsql';


CREATE TRIGGER voipcall_biu_trig1 BEFORE INSERT OR UPDATE ON voipcall
	FOR EACH ROW EXECUTE PROCEDURE voipcall_preprocess_fields();
CREATE TRIGGER voipcall_biu_trig2 BEFORE INSERT OR UPDATE ON voipcall
	FOR EACH ROW EXECUTE PROCEDURE voipcall_match_tariff();
CREATE TRIGGER voipcall_biu_trig3 BEFORE INSERT OR UPDATE ON voipcall
	FOR EACH ROW EXECUTE PROCEDURE voipcall_update_cost();
