<%@ Page Title="About" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="About.aspx.cs" Inherits="test_sso_new1.About" %>

<asp:Content ID="BodyContent" ContentPlaceHolderID="MainContent" runat="server">
    <h2><%: Title %>.</h2>
    <h3>Welcome, <asp:Label ID="Label1" runat="server" Text=""></asp:Label>!</h3>
    <p>
        <asp:Label ID="Label2" runat="server" Text=""></asp:Label>
    </p>
</asp:Content>
