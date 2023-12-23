/** 
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package org.codelibs.spnego;

/**
 * Defines an object for performing user authorization (authZ). See the 
 * javadoc of the {@link UserAccessControl} interface and the {@link LdapAccessControl} 
 * class for more details about the default underlying implementation that 
 * this interface relies upon.
 * 
 * <p>
 * In simple terms, roles are attributes that belong to a user and that an attribute 
 * is something that MUST exist in an attribute set. This treatment is somewhat similar 
 * to the traditional sense that users are assigned roles and/or role_groups. 
 * </p>
 * 
 * <p>
 * One dissimilarity is that an attribute MUST exist in an attribute set. Another is   
 * that users are defined only by their attributes and not by their attribute sets. 
 * This is in contrast to the role based approach where roles do not have to belong 
 * to a role_group.  In addition, a role_group can be concretely assigned to a user, 
 * whereas an attribute set can NOT be concretely assigned to a user.
 * </p>
 * 
 * <p>
 * Some example attribute sets within an Organization might include: Job Title, 
 * Company Department, Company Division, Company Location, Active Directory 
 * Group, Email Distribution List, etc. An attribute set is unique within the set 
 * of all attribute sets. An attribute MUST exist in only one attribute set. Hence, an 
 * example where job titles might include titles such as Developer, Manager, 
 * Analyst, HR Admin, Account Executive, and Receptionist, any and all job titles 
 * MUST exist in only one attribute set AND they MUST all be in the same attribute set.
 * </p>
 * 
 * <p>
 * In the example above, the source of attribute information is defined as 
 * existing in an LDAP/Active Directory Group, User Department, Email Distribution 
 * List, etc. A policy is configured to search one of these attribute sets or optionally 
 * to search all of these attribute sets. The attribute sets can be mixed to allow 
 * for a more expressive policy statement. e.g. 1) A user has access if they are 
 * in <i>this</i> AD Group and belong in one of <i>these</i> departments, or 
 * 2) a user has access if they are in <i>this</i> email distribution list 
 * and in one of <i>these</i> AD Groups or is in one <i>these</i> departments, 
 * or 3) a user can see <i>the edit button</i> if they are in <i>this</i> 
 * AD Group and in one of <i>these</i> other AD Groups.
 * </p>
 * 
 * <p>
 * <b>Attribute Set Example Scenario:</b><br>
 * This example will assume Active Directory (AD) as the data store for user information. 
 * It also assumes that in AD there are three AD Groups named <code>File Share Access</code>, 
 * <code>Finance London</code>, and <code>Desktop Support</code>. Finally, we assume
 * that the department attribute in AD's user profile is populated 
 * for each user. Example values in the department attribute set might be 
 * <code>IT</code>, <code>Accounting</code>, or <code>HR</code>. Under this scenario, 
 * AD Group would be one attribute set and department would be another attribute set. 
 * </p>
 * 
 * <p>
 * Notice that you concretely assign an attribute (e.g. <code>Accounting</code>) to a 
 * user but you can't assign an attribute set (e.g. department to a user). For example, 
 * the attribute set department contains many attributes within it: <code>IT</code>, 
 * <code>Accounting</code>, and <code>HR</code>. 
 * </p>
 * 
 * <p>
 * <b>Example Usage 1:</b><br>
 * A web application/service requires authentication (authN) but certain areas 
 * must only be accessed by users who are in the <code>HR</code> department 
 * OR have been added to the AD Group named <code>File Share Access</code> 
 * OR those users who have a value of <code>Desktop Support</code> 
 * in their department attribute in AD.
 * </p>
 * 
 * <pre>
 * boolean hasPermission = false;
 * 
 * String[] attributes = new String[] {"HR", "File Share Access", "Desktop Support"};
 * 
 * if (request instanceof SpnegoAccessControl) {
 *     SpnegoAccessControl accessControl = (SpnegoAccessControl) request;
 *     
 *     hasPermission = accessControl.anyRole(attributes);
 * } 
 * </pre>
 * 
 * <p>
 * In the above example, the method call <code>anyRole</code> will return true 
 * if the user is in the department named HR or the AD Group named "File share Access" 
 * or is in the department named "Desktop Support".
 * </p>
 * 
 * <p>
 * <b>Example Usage 2:</b><br>
 * Certain areas of a web application/service must only be accessed by users who are 
 * in the AD Group <code>File Share Access</code> AND who are in the AD Group 
 * <code>Finance London</code> or who are in the <code>Accounting</code> department.
 * </p>
 * 
 * <pre>
 * boolean hasPermission = false;
 * 
 * String attributeX = "File Share Access";
 * String[] arttributeYs = new String[] {"Finance London", "Accounting"};
 * 
 * if (request instanceof SpnegoAccessControl) {
 *     SpnegoAccessControl accessControl = (SpnegoAccessControl) request;
 *     
 *     hasPermission = accessControl.hasRole(attributeX, attributeYs);
 * } 
 * </pre>
 * 
 * <p>
 * In the above example, if the user has the attribute File Share Access  
 * AND one of the attributeYs (Finance London or Accounting), the method call 
 * <code>hasRole</code> will return true. 
 * </p>
 * 
 * <p>
 * <b>User-defined Resource Label Example:</b>
 * </p>
 * 
 * <p>
 * An alternative to specifying department names, groups, email distribution lists, etc. 
 * is to use a user-defined resource label. Resource labels are optional and hence must  
 * undergo additional configuration before use.   
 * </p>
 *
 * <pre>
 * boolean hasPermission = false;
 * 
 * if (request instanceof SpnegoAccessControl) {
 *     SpnegoAccessControl accessControl = (SpnegoAccessControl) request;
 *     
 *     hasPermission = accessControl.hasAccess("finance-links");
 * } 
 * </pre>
 * 
 * <p>
 * In the above example, the attribute(s) that support the policy is abstracted by the 
 * user-defined resource label named finance-links. Concretely, given the previous example, 
 * the resource label finance-links would be assigned the attributes File Share Access, 
 * Finance London, and Accounting.
 * </p>
 * 
 * <p>
 * <b>The Java HttpServletRequest Interface and it's isUserInRole method</b>
 * </p>
 * <p>
 * In addition to how the {@link jakarta.servlet.http.HttpServletRequest} interface 
 * defines a <code>getRemoteUser</code> method to retrieve the name of the authenticated 
 * (authN) user, the {@link jakarta.servlet.http.HttpServletRequest} interface also defines 
 * an <code>isUserInRole</code> method that  
 * "<i>returns a boolean indicating whether the authenticated user is included in the 
 * specified logical 'role'</i>". In all of the examples above, a Java Cast was 
 * necessary to achieve the functionality of the <code>SpnegoAccessControl</code> 
 * interface. However, the <code>isUserInRole</code> method obviates the need to perform a 
 * Java Cast.
 * </p>
 * 
 * <p>
 * <b>No java cast example:</b>
 * </p>
 * 
 * <pre>
 * boolean hasPermission = request.isUserInRole("File Share Access");
 * </pre>
 * 
 * <p>
 * In the above example, the Java Cast was not necessary because the standard 
 * <code>HttpServletRequest</code> Interface defines the <code>isUserInRole</code> 
 * method and the SPNEGO Library implements the <code>isUserInRole</code> method of 
 * the interface. Although convenient, available, and performs as expected, 
 * the <code>isUserInRole</code> method alone may not be as expressive as the 
 * methods defined in the <code>SpnegoAccessControl</code> interface.  
 * </p>
 * 
 * <p>
 * For more information regarding implementation details, 
 * as well as additional usage examples, please see the javadoc for the 
 * {@link UserAccessControl} interface as well as the javadoc for the 
 * {@link LdapAccessControl} class.
 * </p>
 * 
 * <p>
 * Also, take a look at the <a href="http://spnego.sourceforge.net/reference_docs.html" 
 * target="_blank">reference docs</a> for a complete list of configuration parameters.
 * </p>
 * 
 * <p>
 * Finally, to see a working example and instructions, take a look at the 
 * <a href="http://spnego.sourceforge.net/enable_authZ_ldap.html" 
 * target="_blank">enable authZ with LDAP</a> guide. 
 * </p>
 * 
 * 
 * @author Darwin V. Felix
 *
 */
public interface SpnegoAccessControl {

    /**
     * Checks to see if the user has at least one of the passed-in attributes.
     * 
     * <pre>
     * String[] attributes = new String[] {"Developer", "Los Angeles", "Manager"};
     * 
     * if (accessControl.anyRole(attributes)) {
     *     // will be in here if the user has at least one matching attribute
     * }
     * </pre>
     * 
     * @param attributes e.g. Team Lead, IT, Developer
     * @return true if the user has at least one of the passed-in roles/features
     */
    boolean anyRole(final String... attributes);
    
    /**
     * Checks to see if the user has the passed-in attribute.
     * 
     * <pre>
     * String attribute = "Developer";
     * 
     * if (accessControl.hasRole(attribute)) {
     *     // will be in here if the user has the matching attribute
     * }
     * </pre>
     * 
     * @param attribute e.g. Team Lead, IT, Developer
     * @return true if the user has at least one of the passed-in roles/features 
     */
    boolean hasRole(final String attribute);

    /**
     * Checks to see if the user has the first attribute   
     * AND has at least one of the passed-in attributes.
     * 
     * <pre>
     * String attributeX = "Los Angeles";
     * String[] attributeYs = new String[] {"Developer", "Manager"};
     * 
     * if (accessControl.hasRole(attributeX, attributeYs)) {
     *     // will be in here if the user has attributeX 
     *     // AND has at least one of the attributeYs.
     * }
     * </pre>
     * 
     * @param attributeX e.g. Information Technology
     * @param attributeYs e.g. Team Lead, IT-Architecture-DL
     * @return true if the user has featureX AND at least one the featureYs
     */
    boolean hasRole(final String attributeX, final String... attributeYs); 
    
    /**
     * Checks to see if the user has at least one of the passed-in user-defined 
     * resource labels
     * 
     * <pre>
     * String[] resources = new String[] {"admin-links", "ops-buttons"};
     * 
     * if (accessControl.anyAccess(resources)) {
     *     // will be in here if the user has at least one matching resource
     * }
     * </pre>
     * 
     * @param resources e.g. admin-links, ops-buttons
     * @return true if the user has at least one of the passed-in resources
     */
    boolean anyAccess(final String... resources);
    
    /**
     * Checks to see if the user has access to the user-defined resource label.
     * 
     * <pre>
     * boolean hasPermission = false;
     * 
     * if (request instanceof SpnegoAccessControl) {
     *     SpnegoAccessControl accessControl = (SpnegoAccessControl) request;
     *     
     *     hasPermission = accessControl.hasAccess("finance-links");
     * } 
     * </pre>
     * 
     * @param resource e.g. admin-buttons
     * @return true if the user has access to the user-defined resource
     */
    boolean hasAccess(final String resource);
    
    /**
     * Checks to see if the user has the first user-defined resource label   
     * AND has at least one of the passed-in user-defined resource labels.
     * 
     * <pre>
     * String resourceX = "finance-links";
     * String[] resourceYs = new String[] {"admin-links", "accounting-buttons"};
     * 
     * if (accessControl.hasAccess(resourceX, resourceYs)) {
     *     // will be in here if the user has resourceX 
     *     // AND has at least one of the resourceYs.
     * }
     * </pre>
     * 
     * @param resourceX e.g. finance-links
     * @param resourceYs e.g. admin-links, accounting-buttons
     * @return true if the user has resourceX AND at least one the resourceYs
     */
    boolean hasAccess(final String resourceX, final String... resourceYs);
    
    /**
     * Returns the user's info object.
     * 
     * @return the user's info object
     */
    UserInfo getUserInfo();
}
