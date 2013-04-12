# -*- coding: utf-8 -*-
"""
Domain Name Server

53番の特権ポートを使用するので起動にはroot権限が必要です。
UIDを指定すれば、ポート開いた後にそのユーザの権限で実行されます。
"""
import os
import socket
import datetime
import sys
import traceback
import select

UID = None

"""設定項目
HOST: パケットを受け付けるIPアドレスを指定してください。
PORT: 動作させるポート番号。DNSは53番です。
UID: 実行時のユーザーID
"""

HOST = '0.0.0.0'
PORT = 53
# 実行時のUID
UID = 65534

HEXS = '0123456789abcdef'

# レコードタイプ
RTYPE_A = 1
RTYPE_NS = 2
RTYPE_CNAME = 5
RTYPE_SOA = 6
RTYPE_PTR = 12
RTYPE_HINFO = 13
RTYPE_MX = 15
RTYPE_TXT = 16
RTYPE_AAAA = 28
# 問い合わせ専用
QTYPE_ANY = 255

def crete_rtn2name(_vars):
	"""レコードタイプ(数値)からレコードタイプ文字列を返す関数を返す"""
	keys = [x for x in _vars if x.startswith('RTYPE_')]
	seed = {}
	for k in keys:
		n = _vars.get(k)
		seed[n] = k[6:]
	return lambda x: seed.get(x, 'unknown({})'.format(x))

rtn2name = crete_rtn2name(locals())

# レコードクラス
RCLASS_IN = 1

# レコードデータベース
RECORDS = {}

class Record(object):
	"""レコードの親"""
	RTYPE = 0
	def __init__(self, ttl=3600):
		self._ttl = ttl
	@property
	def ttl(self):
		return self._ttl
	def to_bytes(self):
		"""バイナリへ変換"""
		pass
	def get_record_type(self):
		return self.__class__.RTYPE
	@staticmethod
	def put16(buf, val):
		buf.append((val>>8) & 0xff)
		buf.append(val & 0xff)
	@staticmethod
	def put32(buf, val):
		buf.append((val>>24) & 0xff)
		buf.append((val>>16) & 0xff)
		buf.append((val>>8) & 0xff)
		buf.append(val & 0xff)


class RecordSOA(Record):
	"""SOAレコード定義"""
	RTYPE = RTYPE_SOA
	def __init__(self, ttl, mname, rname, serial, refresh, retry, expire, minimum):
		"""コンストラクタ
		mname: ゾーンのオリジナルor主たるネームサーバ
		rname: 管理者のメールアドレス
		serial: シリアル番号
		"""
		super(RecordSOA, self).__init__(ttl)
		self.mname = DName.from_name(mname)
		self.rname = DName.from_name(rname.replace('@', '.'))
		if serial:
			self.serial = serial
		else:
			# シリアル値が有効でない場合は日付から生成する
			d = datetime.datetime.utcnow()
			self.serial = ((d.year*10000 + d.month*100 + d.day) * 100 +
										 (d.hour*4 + int(d.minute/15)))
		self.refresh = refresh
		self.retry = retry
		self.expire = expire
		self.minimum = minimum
	def to_bytes(self):
		buf = bytearray()
		self.mname.to_bytes(buf)
		self.rname.to_bytes(buf)
		self.put32(buf, self.serial)
		self.put32(buf, self.refresh)
		self.put32(buf, self.retry)
		self.put32(buf, self.expire)
		self.put32(buf, self.minimum)
		return buf
	def __str__(self):
		return 'SOA: {} {} ...'.format(str(self.mname), str(self.rname))

class RecordCNAME(Record):
	"""CNAMEレコード定義"""
	RTYPE = RTYPE_CNAME
	def __init__(self, ttl, cname):
		"""コンストラクタ
		ttl: TTL
		cname: CNAME
		"""
		super(RecordCNAME, self).__init__(ttl)
		self.cname = DName.from_name(cname)
	def to_bytes(self):
		buf = bytearray()
		self.cname.to_bytes(buf)
		return buf
	def __str__(self):
		return 'CNAME: {}'.format(str(self.cname))


class RecordA(Record):
	"""Aレコード定義"""
	RTYPE = RTYPE_A
	def __init__(self, ttl, ipadrs):
		"""
		ttl: TTL
		ipadrs: IPアドレス 'xxx.yyy.zzz.www'形式で
		"""
		super(RecordA, self).__init__(ttl)
		self.ipadrs = ipadrs
		self.parts = [int(x) for x in ipadrs.split('.')]
	def to_bytes(self):
		buf = bytearray()
		map(buf.append, self.parts)
		return buf
	def __str__(self):
		return 'A: {}'.format(self.ipadrs)

class RecordPTR(Record):
	"""PTRレコード定義"""
	RTYPE = RTYPE_PTR
	def __init__(self, ttl, name):
		"""
		ttl: TTL
		name: ホスト名
		"""
		super(RecordPTR, self).__init__(ttl)
		self.dname = DName.from_name(name)
	def to_bytes(self):
		buf = bytearray()
		self.dname.to_bytes(buf)
		return buf
	def __str__(self):
		return 'PTR: {}'.format(self.dname)

class RecordMX(Record):
	"""MXレコード定義"""
	RTYPE = RTYPE_MX
	def __init__(self, ttl, pref, name):
		"""
		ttl: TTL
		pref: 優先度
		name: メール交換用ホスト名
		"""
		super(RecordMX, self).__init__(ttl)
		self.pref = pref
		self.dname = DName.from_name(name)
	def to_bytes(self):
		buf = bytearray()
		buf.append((self.pref>>8) & 0xff)
		buf.append(self.pref & 0xff)
		self.dname.to_bytes(buf)
		return buf
	def __str__(self):
		return 'MX: {}: {}'.format(self.pref, self.dname)

class RecordNS(Record):
	"""NSレコード定義"""
	RTYPE = RTYPE_NS
	def __init__(self, ttl, name):
		"""
		ttl: TTL
		name: ホスト名
		"""
		super(RecordNS, self).__init__(ttl)
		self.dname = DName.from_name(name)
	def to_bytes(self):
		buf = bytearray()
		self.dname.to_bytes(buf)
		return buf
	def __str__(self):
		return 'NS: {}'.format(self.dname)

class RecordTXT(Record):
	"""TXTレコード"""
	RTYPE = RTYPE_TXT
	def __init__(self, ttl, text):
		"""
		ttl: TTL
		text: テキスト
		"""
		super(RecordTXT, self).__init__(ttl)
		self.text = text
		self.binary = text.encode('UTF-8')
	def to_bytes(self):
		buf = bytearray()
		buf.append(len(self.binary))
		map(buf.append, self.binary)
		return buf
	def __str__(self):
		return 'TXT: {}'.format(self.text)

class RecordHINFO(Record):
	"""HINFOレコード定義"""
	RTYPE = RTYPE_HINFO
	def __init__(self, ttl, cpu, os):
		"""
		ttl: TTL
		cpu: CPU name
		os: OS name
		"""
		super(RecordHINFO, self).__init__(ttl)
		self.b_cpu = cpu.encode('UTF-8')
		self.b_os = os.encode('UTF-8')
	def to_bytes(self):
		buf = bytearray()
		buf.append(len(self.b_cpu))
		map(buf.append, self.b_cpu)
		buf.append(len(self.b_os))
		map(buf.append, self.b_os)
		return buf
	def __str__(self):
		return 'HINFO: CPU:{} OS:{}'.format(self.b_cpu, self.b_os)


class DName:
	"""domain-name class"""
	def __init__(self):
		"""do not use."""
		self.parts = []
	@classmethod
	def from_name(cls, name):
		"""create from string"""
		dn = DName()
		dn.parts = name.split('.')
		return dn
	@classmethod
	def from_binary(self, byte_reader):
		"""create from byte sequence"""
		dn = DName()
		while 1:
			ni = byte_reader() # ブロックのバイト数
			if ni==0: break # おわり
			ns = []
			for xx in xrange(0, ni):
				ns.append(byte_reader())
			dn.parts.append(''.join(map(chr, ns)))
		return dn
	def __str__(self):
		return '.'.join(self.parts)
	def to_bytes(self, buf=None):
		"""[長さ][[]][0]"""
		if buf is None:
			buf = bytearray()
		for x in self.parts:
			buf.append(len(x))
			map(buf.append, x)
		buf.append(0)
		return buf


class QueryInfo:
	"""Question section"""
	def __init__(self):
		self.dname = None
		self.qtype = 0
		self.qclass = 0
	def __str__(self):
		if self.qtype==QTYPE_ANY:
			qt = 'ANY'
		else:
			qt = rtn2name(self.qtype)
		qc = {1:'RCLASS_IN'}.get(self.qclass, 'unknown: %s' % (self.qclass,))
		return '{}: {} {}'.format(
			str(self.dname), qt, qc)


def add_record(name, record):
	"""レコードを定義
	name: キーとなる名前
	rtype: リソースタイプ
	record: レコード(Recordクラスのサブクラスのインスタンス)
	格納イメージ: name => {rtype: [record1, record2, ...]}
	"""
	# 名前から該当するレコードの辞書を取得
	r1 = RECORDS.get(name)
	if r1 is None:
		r1 = {}
		RECORDS[name] = r1
	# レコードタイプが一致するものを取得
	rtype = record.get_record_type()
	if rtype==RTYPE_CNAME:
		# A CNAME record is not allowed to coexist with any other data.
		if 0<len(r1.keys()) and RTYPE_CNAME not in r1:
			print 'ignore:', str(record)

	records = r1.get(rtype)
	if records is None:
		records = []
		r1[rtype] = records
	records.append(record)

def find_records(name, rtype):
	"""該当するレコードを返す
	return:
	None: Name Error
	[]:
	"""
	r1 = RECORDS.get(name)
	if r1 is None:
		print 'record not found.', rtype
		return None
	res = []
	if rtype!=QTYPE_ANY:
		res = r1.get(rtype, res)
		if not res and rtype!=RTYPE_CNAME:
			# 見つからなかった場合にCNAMEレコードを検索してみる。
			res = r1.get(RTYPE_CNAME, res)
	else:
		# ANY問い合わせ
		map(res.extend, r1.values())
	return res


def def_a_record(name, ipadrs, ttl, with_ptr=True):
	"""Aレコードとその逆引きを定義します。
	name: 名前
	ipadrs: IPアドレス
	ttl: TTL
	with_ptr: 逆引きも設定する場合はTrue
	"""
	add_record(name, RecordA(ttl, ipadrs))
	if with_ptr:
		# 逆引きも設定する
		rev = ipadrs.split('.')
		rev.reverse()
		rev.extend(['in-addr', 'arpa'])
		rname = '.'.join(rev)
		add_record(rname, RecordPTR(ttl, name))

class Request:
	def __init__(self):
		self.id = 0
		self.flags = 0
		self.qds = []
		self.nss = []
		self.ars = []
	def create_response_template(self):
		"""リクエストパケットから応答パケットのひな型を作る"""
		res = Response()
		res.buf.append((self.id>>8) & 0xff)
		res.buf.append(self.id & 0xff)
		# フラグ
		flags = self.flags
		# Query/Responseを1に、また、
		# Authoritative Answerを1に変える
		flags |= 0x8400
		# Recursion Availableを0にする。
		flags &= 0xff7f
		res.put_16(flags)
		# クエリ数を設定
		res.put_16(len(self.qds))
		# an/ns/arのカウントを0にする
		for x in xrange(0, 3):
			res.put_16(0)
		# クエリをコピー
		for qi in self.qds:
			qi.dname.to_bytes(res.buf)
			res.put_16(qi.qtype)
			res.put_16(qi.qclass)
		return res


class Response:
	def __init__(self):
		self.buf = bytearray()
		self._closed = False
		self.ancount = 0 # 回答数
		self.nscount = 0 # オーソリティ数
		self.arcount = 0 #
	def put_16(self, b2):
		self.buf.append((b2>>8) & 0xff)
		self.buf.append(b2 & 0xff)
	def put_32(self, b4):
		self.buf.append((b4>>24) & 0xff)
		self.buf.append((b4>>16) & 0xff)
		self.buf.append((b4>>8) & 0xff)
		self.buf.append(b4 & 0xff)
	def append_answer(self, qinfo, record):
		# TODO: 圧縮
		self.buf.extend(qinfo.dname.to_bytes())
		# ANYとかA問い合わせに対して、別のレコードが返されるから。
		self.put_16(record.get_record_type())
		self.put_16(qinfo.qclass)
		self.put_32(record.ttl)
		rdata = record.to_bytes()
		self.put_16(len(rdata))
		map(self.buf.append, rdata)
		self.ancount += 1
	def close(self, rcode):
		"""現在保持している情報でバッファを構成する
		rcode: ヘッダに設定するreturn code
		"""
		if self._closed: return
		self._closed = True
		# return code
		self.buf[3] |= rcode & 0x0f
		# 回答数をセット
		self.buf[6] = (self.ancount>>8) & 0xff
		self.buf[7] = self.ancount & 0xff


def find(dname, qtype):
	"""ドメイン名から関係するレコードを取得する"""
	fqdn = str(dname)
	records = find_records(fqdn, qtype)
	if records:
		return records
	# レコード名の先頭かを削っていき、ワイルドカードマッチを試す。
	dn = dname.parts[1:]
	while dn:
		nl = ['*']
		nl.extend(dn)
		nn = '.'.join(nl)
		records = find_records(nn, qtype)
		if records:
			return records
		# 先頭を削る
		dn.pop(0)
	# 見つからなかった
	return []

def resolve(query):
	"""問い合わせを解決する。"""
	try:
		res = query.create_response_template()
		found = 0 # 解決できた問い合わせの数
		for qi in query.qds:
			records = find(qi.dname, qi.qtype)
			print 'Q:', str(qi)
			# append_answer(self, name, rtype, rclass, ttl, rdata):
			print 'records', [str(x) for x in records]
			for r in records:
				res.append_answer(qi, r)
				found += 1
		if 0<found:
			res.close(0)
		else:
			# Name Errorを返す
			res.close(3)
	except Exception as ex:
		res.close(2)
		print ex
		traceback.print_tb(sys.exc_traceback)
	return res

def parse_query(data):
	"""問い合わせ内容を読み込む"""
	req = Request()
	# 1バイトずつ読み込む関数を用意
	n = data.__iter__().next
	def b(_bytes):
		"""連続した_bytesバイトから
		数値をBigEndianで読み込む"""
		iv = 0
		while 0<_bytes:
			iv <<= 8
			iv |= n()
			_bytes -= 1
		return iv
	req.id = b(2)
	req.flags = b(2)
	req.qd_count = b(2)
	req.an_count = b(2)
	req.ns_count = b(2)
	req.ar_count = b(2)
	# 問い合わせ数だけ質問を読む
	for x in xrange(0, req.qd_count):
		q = QueryInfo()
		q.dname = DName.from_binary(n)
		# 問い合わせ種別
		q.qtype = b(2)
		# 問い合わせクラス
		q.qclass = b(2)
		req.qds.append(q)
	return req

def tcp_proc(ssock):
	"""TCPで要求された場合の処理"""
	csock, adrs = ssock.accept()
	print 'TCP', adrs
	# TCPの場合は2バイトのメッセージ長フィールドが付く
	recv = csock.recv(2)
	data = [ord(x) for x in recv]
	dump_buffer(data)
	mlen = data[0]<<8 | data[1]
	recv = csock.recv(mlen)
	data = [ord(x) for x in recv]
	dump_buffer(data)
	query = parse_query(data)
	res = resolve(query)
	if res is not None:
		# メッセージ長を先頭に付加
		mlen = len(res.buf)
		res.buf.insert(0, (mlen>>8) & 0xff)
		res.buf.insert(1, mlen & 0xff)
		print 'res>>>'
		dump_buffer(res.buf)
		print '<<<'
		csock.sendall(res.buf)
	csock.close()

def udp_proc(ssock):
	"""UDPで要求された場合の処理"""
	(pstr, adrs) = ssock.recvfrom(1500)
	print 'UDP', adrs
	data = [ord(x) for x in pstr]
	# dump_buffer(data)
	query = parse_query(data)
	res = resolve(query)
	if res is not None:
		# print 'res>>>'
		# dump_buffer(res.buf)
		# print '<<<'
		ssock.sendto(res.buf, 0, adrs)


def main():
	# 自分のアドレスを設定
	def_a_record('ns1.example.com', '192.168.10.2', 3600)
	def_a_record('ns2.example.com', '192.168.10.3', 3600)
	add_record('example.com', RecordNS(300, '172.20.20.20'))
	add_record('example.com', RecordTXT(8192, 'v=spf1 redirect=_spf.google.com'))
	add_record('example.com', RecordHINFO(36000, 'IBN-5100', 'IBSIS'))

	add_record('example.com', RecordSOA(
			300,
			'ns1.example.com', 'root@example.com', None,
			3600, 1800, 20000, 3600))
	# MXレコード
	add_record('example.com', RecordMX(300, 1, 'ASPMX.L.GOOGLE.COM'))
	add_record('example.com', RecordMX(300, 5, 'ALT1.ASPMX.L.GOOGLE.COM'))
	add_record('example.com', RecordMX(300, 5, 'ALT2.ASPMX.L.GOOGLE.COM'))
	add_record('example.com', RecordMX(300, 10, 'ASPMX2.GOOGLEMAIL.COM'))
	add_record('example.com', RecordMX(300, 10, 'ASPMX3.GOOGLEMAIL.COM'))
	add_record('example.com', RecordMX(300, 25, 'ASPMX4.GOOGLEMAIL.COM'))
	add_record('example.com', RecordMX(300, 30, 'ASPMX5.GOOGLEMAIL.COM'))

	# 設定の一覧表示
	for k in RECORDS:
		print k
		for rt in RECORDS[k]:
			print ' ', rtn2name(rt)
			for r in RECORDS[k][rt]:
				print '   ', str(r)
	print '---'

	# UDPソケットの用意
	ssock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	ssock_udp.bind((HOST, PORT))
	# TCPソケットの用意
	ssock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ssock_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ssock_tcp.bind((HOST, PORT))
	ssock_tcp.listen(3)

	if UID:
		os.setuid(UID)

	while 1:
		rlist, wlist, xlist = select.select([ssock_tcp, ssock_udp], [], [], 5000)
		if ssock_tcp in rlist:
			tcp_proc(ssock_tcp)
		if ssock_udp in rlist:
			udp_proc(ssock_udp)


def b2h(v):
	return ''.join([HEXS[(v>>4)&0xf], HEXS[v&0xf]])

_COLS = 16
def dump_buffer(pack):
	i = _COLS
	for x in pack:
		i -= 1
		print b2h(x),
		if i==0:
			print
			i = _COLS
	print '<<'


if __name__=='__main__':
	main()
