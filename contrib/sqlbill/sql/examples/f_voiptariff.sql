DELETE FROM voiptariff;
INSERT INTO voiptariff (dstid, price) SELECT id, 15.0 FROM voiptariffdst WHERE active;

CREATE TEMPORARY TABLE voiptariff_temp (
  dstname TEXT NOT NULL,
  dstprice NUMERIC(9,4) NOT NULL,
  dstcurr TEXT NOT NULL,
  dstinitinc INT NOT NULL,
  dstreginc INT NOT NULL
);
	
\copy voiptariff_temp(dstname, dstprice, dstcurr, dstinitinc, dstreginc) from 'voiptariff.asc' with delimiter '\t'

UPDATE voiptariff SET price = dstprice, currencysym = dstcurr, 
	initialincrement = dstinitinc, regularincrement = dstreginc
	FROM voiptariff_temp T, voiptariffdst D
	WHERE dstid = D.id AND D.description LIKE T.dstname;
