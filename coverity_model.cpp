// This is the modeling file for Coverity to avoid false positives.
// This code is not supposed to be compiled into the GNU Gatekeeper!

struct _ios_fields {
	int _precision;
};
class ios : public _ios_fields {
	int precision() const { return _precision; }
	int precision(int newp) { return _precision; }
};

// byte swap causes false positive for tainted data
class RadiusPDU {
	unsigned int GetLength() const { __coverity_tainted_data_sanitize__((void *)&m_length); return m_length; }
	int m_length;
};

