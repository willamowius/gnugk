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
	cid INT;
BEGIN
	NEW.h323id := radius_xlat(NEW.h323id);
	NEW.gkid := radius_xlat(NEW.gkid);
	NEW.callingstationid := radius_xlat(NEW.callingstationid);
	NEW.calledstationid := radius_xlat(NEW.calledstationid);
	
	IF NEW.accountid IS NULL THEN
		SELECT INTO NEW.accountid accountid FROM voipuser
			WHERE h323id = NEW.h323id;
	END IF;

	RETURN NEW;
END;
' LANGUAGE 'plpgsql';

-- Find tariff information for the call
CREATE OR REPLACE FUNCTION voipcall_match_tariff()
	RETURNS TRIGGER AS
'
DECLARE
	trf voiptariff%ROWTYPE;
BEGIN
	IF NEW.price IS NOT NULL AND NEW.cost IS NOT NULL THEN
		RETURN NEW;
	END IF;
	
	SELECT INTO trf * FROM match_tariff(NEW.calledstationid);
	
	IF FOUND AND trf.price IS NOT NULL THEN
		NEW.price := trf.price;
		NEW.currencysym := trf.currencysym;
		NEW.tariffdesc := trf.description;
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
	costdiff NUMERIC(9,2);
BEGIN
	IF NEW.price IS NOT NULL THEN
		NEW.cost := round(
			NEW.price::NUMERIC(9,3) * ((NEW.duration + 59::INT) / 60::INT)::NUMERIC(9,3),
			2
			);
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
