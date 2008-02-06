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
	trf voiptariff%ROWTYPE;
	trfdst voiptariffdst%ROWTYPE;
	termaccount voipaccount%ROWTYPE;
	termuser voipuser%ROWTYPE;
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

	trf.id := NULL;
	SELECT INTO trf * FROM match_tariff(NEW.calledstationid, NEW.accountid, NEW.currencysym);
	IF trf.id IS NOT NULL THEN
		SELECT INTO trfdst * FROM voiptariffdst WHERE id = trf.dstid;
	END IF;
	IF NEW.price IS NULL AND NEW.accountid IS NOT NULL AND trf.id IS NOT NULL THEN
		SELECT INTO NEW.price, NEW.tariffdesc, NEW.initialincrement,
				NEW.regularincrement, NEW.graceperiod, NEW.prefix
				trf.price, trfdst.description, trf.initialincrement, trf.regularincrement,
				trf.graceperiod, trfdst.prefix;
	END IF;

	IF trf.id IS NULL OR trfdst.id IS NULL THEN
		RETURN NEW;
	END IF;

	-- check if there exists a terminating tariff
	
	termuser.id := NULL;	
	SELECT INTO termuser * FROM match_terminating_user(NEW.calledstationid, trfdst.exactmatch, NEW.calledstationip);
	IF termuser.id IS NULL THEN
		RETURN NEW;
	END IF;

	SELECT INTO termaccount * FROM voipaccount A JOIN voipuser U ON A.id = U.accountid
		WHERE U.id = termuser.id;

	trf.id := NULL;	
	SELECT INTO trf * FROM match_terminating_tariff(trfdst.id, termaccount.id, termaccount.currencysym);
	IF trf.id IS NOT NULL THEN
		INSERT INTO voipcalltermtariff (callid, accountid, h323id, terminatingip,
				cost, price, currencysym, initialincrement, regularincrement, graceperiod, tariffdesc)
			VALUES (NEW.id, termaccount.id, termuser.h323id, NEW.calledstationip,
				0, trf.price, trf.currencysym, trf.initialincrement, trf.regularincrement,
				trf.graceperiod, trf.description);
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
	oldcost NUMERIC(12,4);
	termtariff voipcalltermtariff%ROWTYPE;
BEGIN
	IF NEW.price IS NOT NULL THEN
		IF NEW.duration <= NEW.graceperiod OR NEW.duration = 0 THEN
			NEW.cost := 0;
		ELSE
			NEW.cost := NEW.price::NUMERIC(12,4) * NEW.initialincrement::NUMERIC(12,4)
				/ 60::NUMERIC(12,4);
			IF NEW.duration > NEW.initialincrement AND NEW.regularincrement > 0 THEN
				NEW.cost := NEW.cost + NEW.price::NUMERIC(12,4) 
					* ((NEW.duration - NEW.initialincrement + NEW.regularincrement - 1)::INT 
						/ NEW.regularincrement::INT)::NUMERIC(12,4) 
					* NEW.regularincrement::NUMERIC(12,4) / 60::NUMERIC(12,4);
			END IF;
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
	SELECT INTO termtariff * FROM voipcalltermtariff WHERE callid = NEW.id;
	IF termtariff.id IS NOT NULL THEN
		IF termtariff.price IS NOT NULL THEN
			oldcost := termtariff.cost;
			IF NEW.duration <= termtariff.graceperiod OR NEW.duration = 0 THEN
				termtariff.cost := 0;
			ELSE
				termtariff.cost := termtariff.price::NUMERIC(12,4) 
					* termtariff.initialincrement::NUMERIC(12,4) / 60::NUMERIC(12,4);
				IF NEW.duration > termtariff.initialincrement AND termtariff.regularincrement > 0 THEN
					termtariff.cost := termtariff.cost + termtariff.price::NUMERIC(12,4) 
						* ((NEW.duration - termtariff.initialincrement + termtariff.regularincrement - 1)::INT 
							/ termtariff.regularincrement::INT)::NUMERIC(12,4) 
						* termtariff.regularincrement::NUMERIC(12,4) / 60::NUMERIC(12,4);
				END IF;
			END IF;
			UPDATE voipcalltermtariff SET cost = termtariff.cost WHERE id = termtariff.id;
			IF termtariff.accountid IS NOT NULL THEN
				IF oldcost IS NULL THEN
					costdiff := termtariff.cost;
				ELSE
					costdiff := termtariff.cost - oldcost;
				END IF;
				UPDATE voipaccount SET balance = balance + costdiff
					WHERE id = termtariff.accountid;
			END IF;
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
