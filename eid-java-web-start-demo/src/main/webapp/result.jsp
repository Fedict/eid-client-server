<%@ page import="be.bosa.eid.server.demo.ResultExtractor" %>
<%@ page import="be.bosa.eid.server.spi.AddressDTO" %>
<%@ page import="be.bosa.eid.server.spi.IdentityDTO" %>
<%@ page import="java.util.Optional" %>
<%--
  ~ eID Client - Server Project.
  ~ Copyright (C) 2018 - 2018 BOSA.
  ~
  ~ This is free software; you can redistribute it and/or modify it under the
  ~ terms of the GNU Lesser General Public License version 3.0 as published by
  ~ the Free Software Foundation.
  ~
  ~ This software is distributed in the hope that it will be useful, but WITHOUT
  ~ ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  ~ FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
  ~ for more details.
  ~
  ~ You should have received a copy of the GNU Lesser General Public License
  ~ along with this software; if not, see https://www.gnu.org/licenses/.
  --%>

<%
	Optional<String> userId = ResultExtractor.getUserId(request);
	Optional<IdentityDTO> identity = ResultExtractor.getIdentity(request);
	Optional<AddressDTO> address = ResultExtractor.getAddress(request);
%>

<html>
<head>
	<title>eID Java Web Start Demo Site: result page</title>
</head>
<body>
<h1>eID Java Web Start Demo Site: result page</h1>

<h2>Your information</h2>
<p>
	User id: <%= userId.orElse("") %><br/>
	Name: <%= identity.map(IdentityDTO::getFirstName).orElse("") %> <%= identity.map(IdentityDTO::getName).orElse("") %><br>
	Address: <%= address.map(AddressDTO::getStreetAndNumber).orElse("") %>, <%= address.map(AddressDTO::getZip).orElse("") %> <%= address.map(AddressDTO::getCity).orElse("") %>
</p>

<h2>Your picture</h2>
<img src="photo?requestId=<%=request.getParameter("requestId")%>">

<p>
	<a href="index.html">Go back</a>
</p>
</body>
</html>